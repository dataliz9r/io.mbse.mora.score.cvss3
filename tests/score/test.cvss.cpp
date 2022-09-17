#define BOOST_TEST_MAIN

#include <boost/test/unit_test.hpp>

#include "score/cvss.h"

BOOST_AUTO_TEST_CASE( CVSS_calculateCVSSFromMetrics_01 )
{
  score::CVSS::ResultT res = score::CVSS::calculateCVSSFromMetrics(
    "P","H","L","N","U","L","L","H"
  );

  std::cout << std::endl;
  std::cout << "baseMetricScore                     = " << res.baseMetricScore << std::endl;
  std::cout << "baseSeverity                        = " << res.baseSeverity << std::endl;
  std::cout << "baseISS                             = " << res.baseISS << std::endl;
  std::cout << "baseImpact                          = " << res.baseImpact << std::endl;
  std::cout << "baseExploitability                  = " << res.baseExploitability << std::endl;
  std::cout << "temporalMetricScore                 = " << res.temporalMetricScore << std::endl;
  std::cout << "temporalSeverity                    = " << res.temporalSeverity << std::endl;
  std::cout << "environmentalMetricScore            = " << res.environmentalMetricScore << std::endl;
  std::cout << "environmentalSeverity               = " << res.environmentalSeverity << std::endl;
  std::cout << "environmentalMISS                   = " << res.environmentalMISS << std::endl;
  std::cout << "environmentalModifiedImpact         = " << res.environmentalModifiedImpact << std::endl;
  std::cout << "environmentalModifiedExploitability = " << res.environmentalModifiedExploitability << std::endl;
  std::cout << std::endl;
  std::cout << "vectorString = " << res.vectorString << std::endl;
  std::cout << std::endl;
}

BOOST_AUTO_TEST_CASE( CVSS_calculateCVSSFromMetrics_02 )
{
  //check for valid results
  score::CVSS::ResultT r1 = score::CVSS::calculateCVSSFromMetrics("P","H","L","N","U","L","L","H");
  BOOST_CHECK_EQUAL( 5.1, r1.baseMetricScore );

  score::CVSS::ResultT r2 = score::CVSS::calculateCVSSFromMetrics("P","L","L","N","U","L","L","H");
  BOOST_CHECK_EQUAL( 5.4, r2.baseMetricScore );

  score::CVSS::ResultT r3 = score::CVSS::calculateCVSSFromMetrics("P","L","L","N","U","H","H","H");
  BOOST_CHECK_EQUAL( 6.6, r3.baseMetricScore );
}


BOOST_AUTO_TEST_CASE( CVSS_generateJSONFromVector_01 )
{
  //check for valid results
  std::string json = score::CVSS::generateJSONFromVector("CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  std::string json_ext = score::CVSS::generateJSONFromVector("CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H",true);

  std::cout << "(1) JSON (minimal)\n\n" << json << std::endl;
  std::cout << "(1) JSON (w/ optionals)\n\n" << json_ext << std::endl;

}

//EOF
