# io.mbse.mora.score.cvss3
## C++ Header-only implementation of the Common Vulnerability Scoring System (CVSS) Version 3.1

The Common Vulnerability Scoring System (CVSS) is an open framework for communicating the characteristics and severity of software vulnerabilities. CVSS consists of three metric groups: Base, Temporal, and Environmental. The Base group represents the intrinsic qualities of a vulnerability that are constant over time and across user environments, the Temporal group reflects the characteristics of a vulnerability that change over time, and the Environmental group represents the characteristics of a vulnerability that are unique to a user's environment. The Base metrics produce a score ranging from 0 to 10, which can then be modified by scoring the Temporal and Environmental metrics. A CVSS score is also represented as a vector string, a compressed textual representation of the values used to derive the score. This document provides the official specification for CVSS version 3.1.

The most current CVSS resources can be found at https://www.first.org/cvss/

CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. FIRST reserves the right to update CVSS and this document periodically at its sole discretion. While FIRST owns all right and interest in CVSS, it licenses it to the public freely for use, subject to the conditions below. Membership in FIRST is not required to use or implement CVSS. FIRST does, however, require that any individual or entity using CVSS give proper attribution, where applicable, that CVSS is owned by FIRST and used by permission. Further, FIRST requires as a condition of use that any individual or entity which publishes scores conforms to the guidelines described in this document and provides both the score and the scoring vector so others can understand how the score was derived.


![CVSS3 Metric Groups: Base, Temporal, and Environmental](https://www.first.org/cvss/v3-1/media/MetricGroups.svg "a title")

Source: https://www.first.org/cvss/specification-document#i5

## Design
The implentation is based on the JavaScript functions from the official CVSS Calculator https://www.first.org/cvss/calculator/cvsscalc31.js

## Usage & Test
```console
foo@bar:~$ git clone git@github.com:dataliz9r/io.mbse.mora.score.cvss3.git
foo@bar:~$ mkdir io.mbse.mora.score.cvss3.build
foo@bar:~$ cd io.mbse.mora.score.cvss3.build
foo@bar:~$ cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release ..\io.mbse.mora.score.cvss3
foo@bar:~$ cmake --build .
foo@bar:~$ bin\test__io.mbse.mora.score.cvss.exe -l success
```

The testcases should render the following output: 

```
C:/xxx/io.mbse.mora.score.cvss3.build>bin/test__io.mbse.mora.score.cvss.exe -l success
Running 3 test cases...
Entering test module "Master Test Suite"
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(7): Entering test case "CVSS_calculateCVSSFromMetrics_01"

baseMetricScore                     = 5.1
baseSeverity                        = Medium
baseISS                             = 0.732304
baseImpact                          = 4.70139
baseExploitability                  = 0.381211
temporalMetricScore                 = 5.1
temporalSeverity                    = Medium
environmentalMetricScore            = 5.1
environmentalSeverity               = Medium
environmentalMISS                   = 0.732304
environmentalModifiedImpact         = 4.70139
environmentalModifiedExploitability = 0.381211

vectorString = CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H

Test case CVSS_calculateCVSSFromMetrics_01 did not check any assertions
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(7): Leaving test case "CVSS_calculateCVSSFromMetrics_01"; testing time: 21172us
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(31): Entering test case "CVSS_calculateCVSSFromMetrics_02"
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(35): info: check 5.1 == r1.baseMetricScore has passed
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(38): info: check 5.4 == r2.baseMetricScore has passed
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(41): info: check 6.6 == r3.baseMetricScore has passed
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(31): Leaving test case "CVSS_calculateCVSSFromMetrics_02"; testing time: 6043us
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(45): Entering test case "CVSS_generateJSONFromVector_01"
(1) JSON (minimal)

{
    "version": "CVSS:3.1",
    "vectorString": "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H",
    "baseScore": 5.1,
    "baseSeverity": "MEDIUM"
}


(1) JSON (w/ optionals)

{
   "version": "CVSS:3.1",
   "vectorString": "CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H",
   "attackVector": "PHYSICAL",
   "attackComplexity": "HIGH",
   "privilegesRequired": "LOW",
   "userInteraction": "NONE",
   "scope": "UNCHANGED",
   "confidentialityImpact": "LOW",
   "integrityImpact": "LOW",
   "availabilityImpact": "HIGH",
   "baseScore": 5.1,
   "baseSeverity": "MEDIUM",
}


Test case CVSS_generateJSONFromVector_01 did not check any assertions
C:/xxx/io.mbse.mora.score.cvss3/tests/score/test.cvss.cpp(45): Leaving test case "CVSS_generateJSONFromVector_01"; testing time: 8814us
Leaving test module "Master Test Suite"; testing time: 53760us

*** No errors detected
```
