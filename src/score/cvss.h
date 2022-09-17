// ***************************************************************************
// C++ Implementation of the CVSS (Common Vulnerability Scoring System)
// based on the original JavaScript distributed by the Forum of Incident
// Response and Security Teams, Inc.
//
// @see https://www.first.org/cvss/calculator/cvsscalc31.js
//
// Copyright (c) 2019, FIRST.ORG, INC., All rights reserved.
// Copyright (c) 2022, Tino Jungebloud, All rights reserved.
//
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//    disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//    following disclaimer in the documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//    products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// ****************************************************************************

#ifndef __score_cvss_h
#define __score_cvss_h

#include <algorithm>
#include <regex>
#include <cmath>
#include <map>

// ----------------------------------------------------------------------------
namespace score {
// ----------------------------------------------------------------------------


/**
 * Common Vulnerability Scoring System
 *
 * @version 3.1
 */
class CVSS {

public:

  struct ResultT {
    bool success;
    std::string errorType; // added to handle case ResultT w/ success = false
    std::string errorMessage; // added to handle case ResultT w/ success = false

    double baseMetricScore;
    std::string baseSeverity;
    double baseISS;
    double baseImpact;
    double baseExploitability;

    double temporalMetricScore;
    std::string temporalSeverity;

    double environmentalMetricScore;
    std::string environmentalSeverity;
    double environmentalMISS;
    double environmentalModifiedImpact;
    double environmentalModifiedExploitability;

    std::string vectorString;

    std::map<std::string,std::string> baseMetricsValues;

    operator bool () const { return success; }
    bool operator < (const ResultT& rhs) const { return baseMetricScore < rhs.baseMetricScore; }
  };

  inline static std::map<std::string, std::map<std::string, double> > Weight = {
    { "AV",  { {"N", 0.85}, {"A", 0.62}, {"L", 0.55}, {"P", 0.20} } },
    { "AC",  { {"H", 0.44}, {"L", 0.77}                           } },
    { "PRU", { {"N", 0.85}, {"L", 0.62}, {"H", 0.27}              } }, // These values are used if Scope is Unchanged
    { "PRC", { {"N", 0.85}, {"L", 0.68}, {"H", 0.50}              } }, // These values are used if Scope is Changed

    { "UI",  { {"N", 0.85}, {"R", 0.62}                           } },
    { "S",   { {"U", 6.42}, {"C", 7.52}                           } }, // Note: not defined as constants in specification
    { "CIA", { {"N", 0.00}, {"L", 0.22}, {"H", 0.56}              } }, // C, I and A have the same weights

    { "E",   { {"X", 1.00}, {"U", 0.19}, {"P", 0.94}, {"F", 0.97}, {"H", 1.00} } }, // ExploitCodeMaturity
    { "RL",  { {"X", 1.00}, {"O", 0.95}, {"T", 0.96}, {"W", 0.97}, {"U", 1.00} } }, // RemediationLevel{
    { "RC",  { {"X", 1.00}, {"U", 0.92}, {"R", 0.96}, {"C", 1.00}              } }, // ReportConfidence

    { "CIAR",{ {"X", 1.00}, {"L", 0.50}, {"M", 1.00}, {"H", 1.50}              } }  // CR, IR and AR have the same weights

  };

  // Severity rating bands, as defined in the CVSS v3.1 specification.
  inline static std::map<std::string, std::pair<double,double> > severityRatings = {
    // name,      {bottom, top}
    { "None",     {0.0, 0.0} },
    { "Low",      {0.1, 3.9} },
    { "Medium",   {4.0, 6.9} },
    { "High",     {7.0, 8.9} },
    { "Critical", {9.0, 10.0}}
  };

  inline static std::map<std::string, std::map<std::string, std::string>> baseMetricsValueNames = {
    { "AV", { {"N","NETWORK"}, {"A","ADJACENT"}, {"L","LOCAL"}, {"P","PHYSICAL"} } },
    { "AC", { {"L","LOW"}, {"H","HIGH"} } },
    { "PR", { {"N","NONE"}, {"L","LOW"}, {"H","HIGH"} } },
    { "UI", { {"N","NONE"}, {"R","REQUIRED"} } },
    { "S",  { {"U","UNCHANGED"}, {"C","CHANGED"} } },
    { "C",  { {"N","NONE"}, {"L","LOW"}, {"H","HIGH"} } },
    { "I",  { {"N","NONE"}, {"L","LOW"}, {"H","HIGH"} } },
    { "A",  { {"N","NONE"}, {"L","LOW"}, {"H","HIGH"} } }
  };

  inline static const std::string CVSSVersionIdentifier = "CVSS:3.1";

  /**
   * Constant used in the formula.
   */
  inline static const double exploitabilityCoefficient = 8.22;

  /**
   * Constant used in the formula.
   */
  inline static const double scopeCoefficient = 1.08;

  /**
   * A regular expression to validate that a CVSS 3.1 vector string is well
   * formed. It checks metrics and metric values. It does not check that a
   * metric is specified more than once and it does not check that all base
   * metrics are present. These checks need to be performed separately.
   */
  inline static const std::string vectorStringRegex =
    "^CVSS:3\\.1/"
    "((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|"
    "E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|"
    "MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\\/)*"
    "(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|"
    "E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|"
    "MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$";

  /**
   * Associative arrays mapping each metric value to the constant defined in the
   * CVSS scoring formula in the CVSS v3.1 specification.
   */
  static ResultT calculateCVSSFromMetrics(

    std::string AttackVector = "undefined",
    std::string AttackComplexity = "undefined",
    std::string PrivilegesRequired = "undefined",
    std::string UserInteraction = "undefined",
    std::string Scope = "undefined",
    std::string Confidentiality = "undefined",
    std::string Integrity = "undefined",
    std::string Availability  = "undefined",

    std::string ExploitCodeMaturity  = "X",
    std::string RemediationLevel = "X",
    std::string ReportConfidence = "X",

    std::string ConfidentialityRequirement = "X",
    std::string IntegrityRequirement = "X",
    std::string AvailabilityRequirement = "X",
    std::string ModifiedAttackVector = "X",
    std::string ModifiedAttackComplexity = "X",
    std::string ModifiedPrivilegesRequired = "X",
    std::string ModifiedUserInteraction = "X",
    std::string ModifiedScope = "X",
    std::string ModifiedConfidentiality = "X",
    std::string ModifiedIntegrity = "X",
    std::string ModifiedAvailability = "X")
  {
    // If input validation fails, this array is populated with strings indicating which metrics failed validation.
    std::vector<std::string> badMetrics;

    // ENSURE ALL BASE METRICS ARE DEFINED
    // We need values for all Base Score metrics to calculate scores.
    // If any Base Score parameters are undefined, create an array of missing metrics and return it with an error.

    if (AttackVector       == "undefined" || AttackVector       == "") { badMetrics.push_back ("AV"); }
    if (AttackComplexity   == "undefined" || AttackComplexity   == "") { badMetrics.push_back ("AC"); }
    if (PrivilegesRequired == "undefined" || PrivilegesRequired == "") { badMetrics.push_back ("PR"); }
    if (UserInteraction    == "undefined" || UserInteraction    == "") { badMetrics.push_back ("UI"); }
    if (Scope              == "undefined" || Scope              == "") { badMetrics.push_back ("S");  }
    if (Confidentiality    == "undefined" || Confidentiality    == "") { badMetrics.push_back ("C");  }
    if (Integrity          == "undefined" || Integrity          == "") { badMetrics.push_back ("I");  }
    if (Availability       == "undefined" || Availability       == "") { badMetrics.push_back ("A");  }

    if (badMetrics.size() > 0)
    {
      std::ostringstream errorMessage;
      std::copy(badMetrics.begin(), badMetrics.end(), std::ostream_iterator<std::string>(errorMessage, ", "));
      return ResultT{
        false,
        "MissingBaseMetric",
        errorMessage.str()
      };
    }


    // STORE THE METRIC VALUES THAT WERE PASSED AS PARAMETERS
    //
    // Temporal and Environmental metrics are optional, so set them to "undefined" ("Not Defined") if no value was passed.

    std::string AV  = AttackVector;
    std::string AC  = AttackComplexity;
    std::string PR  = PrivilegesRequired;
    std::string UI  = UserInteraction;
    std::string S   = Scope;
    std::string C   = Confidentiality;
    std::string I   = Integrity;
    std::string A   = Availability;

    std::string E   = ExploitCodeMaturity;
    std::string RL  = RemediationLevel;
    std::string RC  = ReportConfidence;

    std::string CR  = ConfidentialityRequirement;
    std::string IR  = IntegrityRequirement;
    std::string AR  = AvailabilityRequirement;
    std::string MAV = ModifiedAttackVector;
    std::string MAC = ModifiedAttackComplexity;
    std::string MPR = ModifiedPrivilegesRequired;
    std::string MUI = ModifiedUserInteraction;
    std::string MS  = ModifiedScope;
    std::string MC  = ModifiedConfidentiality;
    std::string MI  = ModifiedIntegrity;
    std::string MA  = ModifiedAvailability;


    // CHECK VALIDITY OF METRIC VALUES
    //
    // Use the Weight object to ensure that, for every metric, the metric value passed is valid.
    // If any invalid values are found, create an array of their metrics and return it with an error.
    //
    // The Privileges Required (PR) weight depends on Scope, but when checking the validity of PR we must not assume
    // that the given value for Scope is valid. We therefore always look at the weights for Unchanged Scope when
    // performing this check. The same applies for validation of Modified Privileges Required (MPR).
    //
    // The Weights object does not contain "X" ("Not Defined") values for Environmental metrics because we replace them
    // with their Base metric equivalents later in the function. For example, an MAV of "X" will be replaced with the
    // value given for AV. We therefore need to explicitly allow a value of "X" for Environmental metrics.

    if (!               CVSS::Weight["AV" ][AV])   {badMetrics.push_back("AV");}
    if (!               CVSS::Weight["AC" ][AC])   {badMetrics.push_back("AC");}
    if (!               CVSS::Weight["PRU"][PR])   {badMetrics.push_back("PR");}
    if (!               CVSS::Weight["UI" ][UI])   {badMetrics.push_back("UI");}
    if (!               CVSS::Weight["S"  ][S] )   {badMetrics.push_back("S"); }
    if (!               CVSS::Weight["CIA"][C] )   {badMetrics.push_back("C"); }
    if (!               CVSS::Weight["CIA"][I] )   {badMetrics.push_back("I"); }
    if (!               CVSS::Weight["CIA"][A] )   {badMetrics.push_back("A"); }

    if (!               CVSS::Weight["E"  ][E ])   {badMetrics.push_back("E"); }
    if (!               CVSS::Weight["RL" ][RL])   {badMetrics.push_back("RL");}
    if (!               CVSS::Weight["RC" ][RC])   {badMetrics.push_back("RC");}

    if (!(CR  == "X" || CVSS::Weight["CR" ][CR ])) {badMetrics.push_back("CR"); }
    if (!(IR  == "X" || CVSS::Weight["IR" ][IR ])) {badMetrics.push_back("IR"); }
    if (!(AR  == "X" || CVSS::Weight["AR" ][AR ])) {badMetrics.push_back("AR"); }
    if (!(MAV == "X" || CVSS::Weight["MAV"][MAV])) {badMetrics.push_back("MAV");}
    if (!(MAC == "X" || CVSS::Weight["MAC"][MAC])) {badMetrics.push_back("MAC");}
    if (!(MPR == "X" || CVSS::Weight["MPR"][MPR])) {badMetrics.push_back("MPR");}
    if (!(MUI == "X" || CVSS::Weight["MUI"][MUI])) {badMetrics.push_back("MUI");}
    if (!(MS  == "X" || CVSS::Weight["MS" ][MS ])) {badMetrics.push_back("MS"); }
    if (!(MC  == "X" || CVSS::Weight["MC" ][MC ])) {badMetrics.push_back("MC"); }
    if (!(MI  == "X" || CVSS::Weight["MI" ][MI ])) {badMetrics.push_back("MI"); }
    if (!(MA  == "X" || CVSS::Weight["MA" ][MA ])) {badMetrics.push_back("MA"); }


    if (badMetrics.size() > 0)
    {
      std::ostringstream errorMessage;
      std::copy(badMetrics.begin(), badMetrics.end(), std::ostream_iterator<std::string>(errorMessage, ", "));

      return ResultT{
        false,
        "UnknownMetricValue",
        errorMessage.str()
      };
    }


    // GATHER WEIGHTS FOR ALL METRICS

    double metricWeightAV  = CVSS::Weight["AV"]    [AV];
    double metricWeightAC  = CVSS::Weight["AC"]    [AC];
    double metricWeightPR  = CVSS::Weight["PR"+S]  [PR];// PR depends on the value of Scope (S).
    double metricWeightUI  = CVSS::Weight["UI"]    [UI];
    double metricWeightS   = CVSS::Weight["S"]     [S];
    double metricWeightC   = CVSS::Weight["CIA"]   [C];
    double metricWeightI   = CVSS::Weight["CIA"]   [I];
    double metricWeightA   = CVSS::Weight["CIA"]   [A];

    double metricWeightE   = CVSS::Weight["E"]     [E];
    double metricWeightRL  = CVSS::Weight["RL"]    [RL];
    double metricWeightRC  = CVSS::Weight["RC"]    [RC];

    // For metrics that are modified versions of Base Score metrics, e.g. Modified Attack Vector, use the value of
    // the Base Score metric if the modified version value is "X" ("Not Defined").
    double metricWeightCR  = CVSS::Weight["CIAR"]  [CR];
    double metricWeightIR  = CVSS::Weight["CIAR"]  [IR];
    double metricWeightAR  = CVSS::Weight["CIAR"]  [AR];
    double metricWeightMAV = CVSS::Weight["AV"]    [MAV != "X" ? MAV : AV];
    double metricWeightMAC = CVSS::Weight["AC"]    [MAC != "X" ? MAC : AC];
    double metricWeightMPR = CVSS::Weight["PR"+(MS!="X"?MS:S)][MPR!="X"?MPR:PR]; // Depends on MS.
    double metricWeightMUI = CVSS::Weight["UI"]    [MUI != "X" ? MUI : UI];
    double metricWeightMS  = CVSS::Weight["S"]     [MS  != "X" ? MS  : S];
    double metricWeightMC  = CVSS::Weight["CIA"]   [MC  != "X" ? MC  : C];
    double metricWeightMI  = CVSS::Weight["CIA"]   [MI  != "X" ? MI  : I];
    double metricWeightMA  = CVSS::Weight["CIA"]   [MA  != "X" ? MA  : A];



    // CALCULATE THE CVSS BASE SCORE

    double iss; /* Impact Sub-Score */
    double impact;
    double exploitability;
    double baseScore;

    iss = (1 - ((1 - metricWeightC) * (1 - metricWeightI) * (1 - metricWeightA)));

    if (S == "U")
    {
      impact = metricWeightS * iss;
    }
    else
    {
      impact = metricWeightS * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15);
    }

    exploitability = CVSS::exploitabilityCoefficient * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI;

    if (impact <= 0)
    {
      baseScore = 0;
    }
    else
    {
      if (S == "U")
      {
        baseScore = CVSS::roundUp1(std::min((exploitability + impact), 10.0));
      }
      else
      {
        baseScore = CVSS::roundUp1(std::min(CVSS::scopeCoefficient * (exploitability + impact), 10.0));
      }
    }

    // CALCULATE THE CVSS TEMPORAL SCORE

    double temporalScore = CVSS::roundUp1(baseScore * metricWeightE * metricWeightRL * metricWeightRC);


    // CALCULATE THE CVSS ENVIRONMENTAL SCORE
    //
    // - modifiedExploitability recalculates the Base Score Exploitability sub-score using any modified values from the
    //   Environmental metrics group in place of the values specified in the Base Score, if any have been defined.
    // - modifiedImpact recalculates the Base Score Impact sub-score using any modified values from the
    //   Environmental metrics group in place of the values specified in the Base Score, and any additional weightings
    //   given in the Environmental metrics group.

    double miss; /* Modified Impact Sub-Score */
    double modifiedImpact;
    double envScore;
    double modifiedExploitability;

    miss = std::min (  1 -
                    ( (1 - metricWeightMC * metricWeightCR) *
                      (1 - metricWeightMI * metricWeightIR) *
                      (1 - metricWeightMA * metricWeightAR)), 0.915);

    if ( (MS == "U"            ) ||
         (MS == "X" && S == "U") )
    {
      modifiedImpact = metricWeightMS * miss;
    }
    else
    {
      modifiedImpact = metricWeightMS * (miss - 0.029) - 3.25 * std::pow(miss * 0.9731 - 0.02, 13);
    }

    modifiedExploitability = CVSS::exploitabilityCoefficient * metricWeightMAV * metricWeightMAC * metricWeightMPR * metricWeightMUI;

    if (modifiedImpact <= 0)
    {
      envScore = 0;
    }
    else if (MS == "U" || (MS == "X" && S == "U"))
    {
      envScore = CVSS::roundUp1(CVSS::roundUp1(std::min((modifiedImpact + modifiedExploitability), 10.0)) *
                                metricWeightE * metricWeightRL * metricWeightRC);
    }
    else
    {
      envScore = CVSS::roundUp1(CVSS::roundUp1(std::min(CVSS::scopeCoefficient * (modifiedImpact + modifiedExploitability), 10.0)) *
                                metricWeightE * metricWeightRL * metricWeightRC);
    }


    // CONSTRUCT THE VECTOR STRING

    std::string vectorString =
      CVSS::CVSSVersionIdentifier +
      "/AV:" + AV +
      "/AC:" + AC +
      "/PR:" + PR +
      "/UI:" + UI +
      "/S:"  + S +
      "/C:"  + C +
      "/I:"  + I +
      "/A:"  + A;

    if (E   != "X") {vectorString = vectorString + "/E:"   + E;}
    if (RL  != "X") {vectorString = vectorString + "/RL:"  + RL;}
    if (RC  != "X") {vectorString = vectorString + "/RC:"  + RC;}

    if (CR  != "X") {vectorString = vectorString + "/CR:"  + CR;}
    if (IR  != "X") {vectorString = vectorString + "/IR:"  + IR;}
    if (AR  != "X") {vectorString = vectorString + "/AR:"  + AR;}
    if (MAV != "X") {vectorString = vectorString + "/MAV:" + MAV;}
    if (MAC != "X") {vectorString = vectorString + "/MAC:" + MAC;}
    if (MPR != "X") {vectorString = vectorString + "/MPR:" + MPR;}
    if (MUI != "X") {vectorString = vectorString + "/MUI:" + MUI;}
    if (MS  != "X") {vectorString = vectorString + "/MS:"  + MS;}
    if (MC  != "X") {vectorString = vectorString + "/MC:"  + MC;}
    if (MI  != "X") {vectorString = vectorString + "/MI:"  + MI;}
    if (MA  != "X") {vectorString = vectorString + "/MA:"  + MA;}

    return ResultT{
      /* success */ true,
      /* errorType*/ std::string(),
      /* errorMessage*/ std::string(),

      /* baseMetricScore */ baseScore,
      /* baseSeverity */ CVSS::severityRating(baseScore),
      /* baseISS */ iss,
      /* baseImpact */ impact,
      /* baseExploitability */ exploitability,

      /* temporalMetricScore */ temporalScore,
      /* temporalSeverity */ CVSS::severityRating( temporalScore ),

      /* environmentalMetricScore */ envScore,
      /* environmentalSeverity */ CVSS::severityRating( envScore ),
      /* environmentalMISS */ miss,
      /* environmentalModifiedImpact */ modifiedImpact,
      /* environmentalModifiedExploitability */  modifiedExploitability,

      /* vectorString */ vectorString,

      /* baseMetricsValues */ {
        {"AV",AV},{"AC",AC},{"PR",PR},{"UI",UI},
        {"S" , S},{"C" , C},{"I" , I},{"A" , A}
      }
    };

  };

  /* ** CVSS31.calculateCVSSFromVector **
   *
   * Takes Base, Temporal and Environmental metric values as a single string in the Vector String format defined
   * in the CVSS v3.1 standard definition of the Vector String.
   *
   * Returns Base, Temporal and Environmental scores, severity ratings, and an overall Vector String. All Base metrics
   * are required to generate this output. All Temporal and Environmental metric values are optional. Any that are not
   * passed default to "X" ("Not Defined").
   *
   * See the comment for the CVSS31.calculateCVSSFromMetrics function for details on the function output. In addition to
   * the error conditions listed for that function, this function can also return:
   *   "MalformedVectorString", if the Vector String passed does not conform to the format in the standard; or
   *   "MultipleDefinitionsOfMetric", if the Vector String is well formed but defines the same metric (or metrics),
   *                                  more than once.
   */
  static ResultT calculateCVSSFromVector(std::string vectorString)
  {
    std::map<std::string, std::string> metricValues = {
      {"AV", "undefined"}, {"AC", "undefined"}, {"PR", "undefined"}, {"UI", "undefined"}, {"S", "undefined"},
      {"C",  "undefined"}, {"I",  "undefined"}, {"A",  "undefined"},

      {"E",  "X"}, {"RL", "X"}, {"RC", "X"},
      {"CR", "X"}, {"IR", "X"}, {"AR", "X"},
      {"MAV","X"}, {"MAC","X"}, {"MPR","X"}, {"MUI","X"}, {"MS","X"},
      {"MC" ,"X"}, {"MI", "X"}, {"MA", "X"}
    };

    // If input validation fails, this array is populated with strings indicating which metrics failed validation.
    std::vector<std::string> badMetrics;


    if (!std::regex_match(vectorString, std::regex(CVSS::vectorStringRegex)))
    {
      return ResultT{
        false,
        "MalformedVectorString"
      };
    }

    std::vector<std::string> metricNameValues;

    // split by '/'
    // {
    std::istringstream vectorStringSS(vectorString.substr(CVSSVersionIdentifier.length() + 1));
    std::string vectorStringToken;
    while (std::getline(vectorStringSS, vectorStringToken, '/')) {
      metricNameValues.push_back(vectorStringToken);
    }
    // }

    for(std::string& p : metricNameValues)
    {
      std::string singleMetricName = p.substr(0, p.find(':'));
      std::string singleMetricValue = p.substr(p.find(':')+1);

      if (metricValues[singleMetricName] == "undefined")
      {
        metricValues[singleMetricName] = singleMetricValue;
      }
      else
      {
        badMetrics.push_back(singleMetricName);
      }
    }

    if (badMetrics.size() > 0)
    {
      std::ostringstream errorMessage;
      std::copy(badMetrics.begin(), badMetrics.end(), std::ostream_iterator<std::string>(errorMessage, ", "));

      return ResultT{
        false,
        "MultipleDefinitionsOfMetric",
        errorMessage.str()
      };
    }

    return calculateCVSSFromMetrics (
      metricValues["AV"],  metricValues["AC"],  metricValues["PR"],  metricValues["UI"],  metricValues["S"],
      metricValues["C"],   metricValues["I"],   metricValues["A"],
      metricValues["E"],   metricValues["RL"],  metricValues["RC"],
      metricValues["CR"],  metricValues["IR"],  metricValues["AR"],
      metricValues["MAV"], metricValues["MAC"], metricValues["MPR"], metricValues["MUI"], metricValues["MS"],
      metricValues["MC"],  metricValues["MI"],  metricValues["MA"]);
  }

  /* ** CVSS31.roundUp1 **
   *
   * Rounds up its parameter to 1 decimal place and returns the result.
   *
   * Standard JavaScript errors thrown when arithmetic operations are performed on non-numbers will be returned if the
   * given input is not a number.
   *
   * Implementation note: Tiny representation errors in floating point numbers makes rounding complex. For example,
   * consider calculating Math.ceil((1-0.58)*100) by hand. It can be simplified to Math.ceil(0.42*100), then
   * Math.ceil(42), and finally 42. Most JavaScript implementations give 43. The problem is that, on many systems,
   * 1-0.58 = 0.42000000000000004, and the tiny error is enough to push ceil up to the next integer. The implementation
   * below avoids such problems by performing the rounding using integers. The input is first multiplied by 100,000
   * and rounded to the nearest integer to consider 6 decimal places of accuracy, so 0.000001 results in 0.0, but
   * 0.000009 results in 0.1.
   *
   * A more elegant solution may be possible, but the following gives answers consistent with results from an arbitrary
   * precision library.
   */
  static double roundUp1(double input)
  {
    double int_input = round(input * 100000);

    if (std::remainder(int_input,10000) == 0)
    {
      return int_input / 100000;
    }
    else
    {
      return (floor(int_input / 10000) + 1) / 10;
    }
  };


  /* ** CVSS31.severityRating **
   *
   * Given a CVSS score, returns the name of the severity rating as defined in the CVSS standard.
   * The input needs to be a number between 0.0 to 10.0, to one decimal place of precision.
   *
   * The following error values may be returned instead of a severity rating name:
   *   NaN (JavaScript "Not a Number") - if the input is not a number.
   *   undefined - if the input is a number that is not within the range of any defined severity rating.
   */
  static std::string severityRating (double score)
  {
    unsigned int severityRatingLength = CVSS::severityRatings.size();

    std::string validatedScore = std::to_string(score);

    if (!std::regex_match(validatedScore, std::regex("^[0-9]+\\.?[0-9]*$")))
      return "NaN";

    for(auto& key_val : CVSS::severityRatings)
    {
      if (score >= key_val.second.first && score <= key_val.second.second)
      {
        return key_val.first;
      }
    }

    return "undefined";
  };

  /**
   * Not part of the official CVSS31.js
   *
   * @see https://www.first.org/cvss/data-representations
   */
  static std::string generateJSONFromVector(std::string vectorString, bool optionals = false)
  {

    ResultT res = calculateCVSSFromVector(vectorString);

    std::string json =
    "{\n"
    "    \"version\": \"__version__\",\n"
    "    \"vectorString\": \"__vectorString__\",\n"
    "    \"baseScore\": __baseMetricScore__,\n"
    "    \"baseSeverity\": \"__baseSeverity__\"\n"
    "}\n\n";

    std::string json_ext =
    "{\n"
    "   \"version\": \"__version__\",\n"
    "   \"vectorString\": \"__vectorString__\",\n"
    "   \"attackVector\": \"__AV__\",\n"
    "   \"attackComplexity\": \"__AC__\",\n"
    "   \"privilegesRequired\": \"__PR__\",\n"
    "   \"userInteraction\": \"__UI__\",\n"
    "   \"scope\": \"__S__\",\n"
    "   \"confidentialityImpact\": \"__C__\",\n"
    "   \"integrityImpact\": \"__I__\",\n"
    "   \"availabilityImpact\": \"__A__\",\n"
    "   \"baseScore\": __baseMetricScore__,\n"
    "   \"baseSeverity\": \"__baseSeverity__\",\n"
    "}\n\n";

    std::ostringstream baseMetricScore;
    baseMetricScore.precision(1);
    baseMetricScore << std::fixed << res.baseMetricScore;

    std::string baseSeverity(res.baseSeverity);
    std::transform(baseSeverity.cbegin(), baseSeverity.cend(), baseSeverity.begin(),
      [](unsigned char c) {return std::toupper(c);});

    //minimal
    json = std::regex_replace(json, std::regex("__version__"), CVSS::CVSSVersionIdentifier);
    json = std::regex_replace(json, std::regex("__vectorString__"), vectorString);
    json = std::regex_replace(json, std::regex("__baseMetricScore__"), baseMetricScore.str());
    json = std::regex_replace(json, std::regex("__baseSeverity__"), baseSeverity);

    //including optional
    json_ext = std::regex_replace(json_ext, std::regex("__version__"), CVSS::CVSSVersionIdentifier);
    json_ext = std::regex_replace(json_ext, std::regex("__vectorString__"), vectorString);
    json_ext = std::regex_replace(json_ext, std::regex("__AV__"), baseMetricsValueNames["AV"][res.baseMetricsValues["AV"]]);
    json_ext = std::regex_replace(json_ext, std::regex("__AC__"), baseMetricsValueNames["AC"][res.baseMetricsValues["AC"]]);
    json_ext = std::regex_replace(json_ext, std::regex("__PR__"), baseMetricsValueNames["PR"][res.baseMetricsValues["PR"]]);
    json_ext = std::regex_replace(json_ext, std::regex("__UI__"), baseMetricsValueNames["UI"][res.baseMetricsValues["UI"]]);
    json_ext = std::regex_replace(json_ext, std::regex("__S__"),  baseMetricsValueNames["S"][res.baseMetricsValues["S"]]);
    json_ext = std::regex_replace(json_ext, std::regex("__C__"),  baseMetricsValueNames["C"][res.baseMetricsValues["C"]]);
    json_ext = std::regex_replace(json_ext, std::regex("__I__"),  baseMetricsValueNames["C"][res.baseMetricsValues["I"]]);
    json_ext = std::regex_replace(json_ext, std::regex("__A__"),  baseMetricsValueNames["C"][res.baseMetricsValues["A"]]);
    json_ext = std::regex_replace(json_ext, std::regex("__baseMetricScore__"), baseMetricScore.str());
    json_ext = std::regex_replace(json_ext, std::regex("__baseSeverity__"), baseSeverity);

    return optionals?json_ext:json;
  }


};

typedef CVSS CVSS31;

// ----------------------------------------------------------------------------
}//end namespace
// ----------------------------------------------------------------------------

#endif

//EOF
