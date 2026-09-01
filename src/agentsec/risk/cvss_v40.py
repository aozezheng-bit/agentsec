"""CVSS v4.0 Base Score calculation using the official MacroVector method.

The lookup values and MacroVector maxima are derived from the CVSS v4.0
reference implementation maintained by FIRST.ORG and Red Hat.  The reference
implementation's lookup table is BSD-2-Clause licensed; its attribution is
retained here because the table is normative data for the v4.0 calculator.

Reference:
https://github.com/RedHatProductSecurity/cvss/blob/master/cvss/constants4.py
https://www.first.org/cvss/v4-0/specification-document
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal

CVSS_V40_CALCULATION_BASIS = (
    "FIRST CVSS v4.0 Base Metrics, MacroVector interpolation, and lookup table",
    "AgentSec local CVSS v4.0 calculator contract 0.2.0",
)

# Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors.
# The lookup table data is redistributed under the BSD-2-Clause terms used by
# the reference implementation. See the module docstring for source links.

_LOOKUP_DATA = """
000000 10
000001 9.9
000010 9.8
000011 9.5
000020 9.5
000021 9.2
000100 10
000101 9.6
000110 9.3
000111 8.7
000120 9.1
000121 8.1
000200 9.3
000201 9
000210 8.9
000211 8
000220 8.1
000221 6.8
001000 9.8
001001 9.5
001010 9.5
001011 9.2
001020 9
001021 8.4
001100 9.3
001101 9.2
001110 8.9
001111 8.1
001120 8.1
001121 6.5
001200 8.8
001201 8
001210 7.8
001211 7
001220 6.9
001221 4.8
002001 9.2
002011 8.2
002021 7.2
002101 7.9
002111 6.9
002121 5
002201 6.9
002211 5.5
002221 2.7
010000 9.9
010001 9.7
010010 9.5
010011 9.2
010020 9.2
010021 8.5
010100 9.5
010101 9.1
010110 9
010111 8.3
010120 8.4
010121 7.1
010200 9.2
010201 8.1
010210 8.2
010211 7.1
010220 7.2
010221 5.3
011000 9.5
011001 9.3
011010 9.2
011011 8.5
011020 8.5
011021 7.3
011100 9.2
011101 8.2
011110 8
011111 7.2
011120 7
011121 5.9
011200 8.4
011201 7
011210 7.1
011211 5.2
011220 5
011221 3
012001 8.6
012011 7.5
012021 5.2
012101 7.1
012111 5.2
012121 2.9
012201 6.3
012211 2.9
012221 1.7
100000 9.8
100001 9.5
100010 9.4
100011 8.7
100020 9.1
100021 8.1
100100 9.4
100101 8.9
100110 8.6
100111 7.4
100120 7.7
100121 6.4
100200 8.7
100201 7.5
100210 7.4
100211 6.3
100220 6.3
100221 4.9
101000 9.4
101001 8.9
101010 8.8
101011 7.7
101020 7.6
101021 6.7
101100 8.6
101101 7.6
101110 7.4
101111 5.8
101120 5.9
101121 5
101200 7.2
101201 5.7
101210 5.7
101211 5.2
101220 5.2
101221 2.5
102001 8.3
102011 7
102021 5.4
102101 6.5
102111 5.8
102121 2.6
102201 5.3
102211 2.1
102221 1.3
110000 9.5
110001 9
110010 8.8
110011 7.6
110020 7.6
110021 7
110100 9
110101 7.7
110110 7.5
110111 6.2
110120 6.1
110121 5.3
110200 7.7
110201 6.6
110210 6.8
110211 5.9
110220 5.2
110221 3
111000 8.9
111001 7.8
111010 7.6
111011 6.7
111020 6.2
111021 5.8
111100 7.4
111101 5.9
111110 5.7
111111 5.7
111120 4.7
111121 2.3
111200 6.1
111201 5.2
111210 5.7
111211 2.9
111220 2.4
111221 1.6
112001 7.1
112011 5.9
112021 3
112101 5.8
112111 2.6
112121 1.5
112201 2.3
112211 1.3
112221 0.6
200000 9.3
200001 8.7
200010 8.6
200011 7.2
200020 7.5
200021 5.8
200100 8.6
200101 7.4
200110 7.4
200111 6.1
200120 5.6
200121 3.4
200200 7
200201 5.4
200210 5.2
200211 4
200220 4
200221 2.2
201000 8.5
201001 7.5
201010 7.4
201011 5.5
201020 6.2
201021 5.1
201100 7.2
201101 5.7
201110 5.5
201111 4.1
201120 4.6
201121 1.9
201200 5.3
201201 3.6
201210 3.4
201211 1.9
201220 1.9
201221 0.8
202001 6.4
202011 5.1
202021 2
202101 4.7
202111 2.1
202121 1.1
202201 2.4
202211 0.9
202221 0.4
210000 8.8
210001 7.5
210010 7.3
210011 5.3
210020 6
210021 5
210100 7.3
210101 5.5
210110 5.9
210111 4
210120 4.1
210121 2
210200 5.4
210201 4.3
210210 4.5
210211 2.2
210220 2
210221 1.1
211000 7.5
211001 5.5
211010 5.8
211011 4.5
211020 4
211021 2.1
211100 6.1
211101 5.1
211110 4.8
211111 1.8
211120 2
211121 0.9
211200 4.6
211201 1.8
211210 1.7
211211 0.7
211220 0.8
211221 0.2
212001 5.3
212011 2.4
212021 1.4
212101 2.4
212111 1.2
212121 0.5
212201 1
212211 0.3
212221 0.1
"""

CVSS_V40_LOOKUP: dict[str, float] = {
    key: float(value)
    for key, value in (line.split() for line in _LOOKUP_DATA.splitlines() if line)
}

_EQ1_MAX = {
    0: ("AV:N/PR:N/UI:N/",),
    1: ("AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"),
    2: ("AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"),
}
_EQ2_MAX = {
    0: ("AC:L/AT:N/",),
    1: ("AC:H/AT:N/", "AC:L/AT:P/"),
}
_EQ3_MAX: dict[int, dict[int, tuple[str, ...]]] = {
    0: {
        0: ("VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/",),
        1: (
            "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
            "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/",
        ),
    },
    1: {
        0: (
            "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
            "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/",
        ),
        1: (
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ),
    },
    2: {1: ("VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/",)},
}
_EQ4_MAX = {
    0: ("SC:H/SI:S/SA:S/",),
    1: ("SC:H/SI:H/SA:H/",),
    2: ("SC:L/SI:L/SA:L/",),
}
_EQ5_MAX = {0: ("E:A/",), 1: ("E:P/",), 2: ("E:U/",)}
_MAX_SEVERITY_EQ1 = {0: 1, 1: 4, 2: 5}
_MAX_SEVERITY_EQ2 = {0: 1, 1: 2}
_MAX_SEVERITY_EQ3_EQ6 = {
    0: {0: 7, 1: 6},
    1: {0: 8, 1: 8},
    2: {1: 10},
}
_MAX_SEVERITY_EQ4 = {0: 6, 1: 5, 2: 4}

_AV_LEVELS = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_PR_LEVELS = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI_LEVELS = {"N": 0.0, "P": 0.1, "A": 0.2}
_AC_LEVELS = {"L": 0.0, "H": 0.1}
_AT_LEVELS = {"N": 0.0, "P": 0.1}
_VC_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
_VI_LEVELS = _VC_LEVELS
_VA_LEVELS = _VC_LEVELS
_SC_LEVELS = {"H": 0.1, "L": 0.2, "N": 0.3}
_SI_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
_SA_LEVELS = _SI_LEVELS
_CR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
_IR_LEVELS = _CR_LEVELS
_AR_LEVELS = _CR_LEVELS


def _default_metric(value: str, default: str) -> str:
    return default if value == "X" else value


def _effective_metric(
    metrics: Mapping[str, str], modified_name: str, base_name: str
) -> str:
    return _default_metric(metrics.get(modified_name, "X"), metrics[base_name])


def calculate_cvss_v40_base_score(metrics: Mapping[str, str]) -> float:
    """Calculate a CVSS v4.0 Base Score from the 11 Base Metrics.

    CVSS v4.0 Base input defaults optional scoring metrics to E:A and CR/IR/AR:H.
    The input is expected to have already passed AgentSec's vector parser.
    """

    base = dict(metrics)
    values = {
        "AV": _effective_metric(base, "MAV", "AV"),
        "AC": _effective_metric(base, "MAC", "AC"),
        "AT": _effective_metric(base, "MAT", "AT"),
        "PR": _effective_metric(base, "MPR", "PR"),
        "UI": _effective_metric(base, "MUI", "UI"),
        "VC": _effective_metric(base, "MVC", "VC"),
        "VI": _effective_metric(base, "MVI", "VI"),
        "VA": _effective_metric(base, "MVA", "VA"),
        "SC": _effective_metric(base, "MSC", "SC"),
        "SI": _effective_metric(base, "MSI", "SI"),
        "SA": _effective_metric(base, "MSA", "SA"),
        "E": _default_metric(base.get("E", "X"), "A"),
        "CR": _default_metric(base.get("CR", "X"), "H"),
        "IR": _default_metric(base.get("IR", "X"), "H"),
        "AR": _default_metric(base.get("AR", "X"), "H"),
    }
    if all(values[metric] == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro_vector = _macro_vector(values)
    value = CVSS_V40_LOOKUP[macro_vector]
    levels = tuple(int(item) for item in macro_vector)

    lower_scores = _lower_macro_scores(levels)
    max_vectors = _max_vectors(levels)
    current_distances = _find_max_vector_distances(values, max_vectors)

    distances = {
        "eq1": current_distances[0],
        "eq2": current_distances[1],
        "eq3eq6": current_distances[2],
        "eq4": current_distances[3],
    }
    max_severity = {
        "eq1": _MAX_SEVERITY_EQ1[levels[0]] * 0.1,
        "eq2": _MAX_SEVERITY_EQ2[levels[1]] * 0.1,
        "eq3eq6": _MAX_SEVERITY_EQ3_EQ6[levels[2]][levels[5]] * 0.1,
        "eq4": _MAX_SEVERITY_EQ4[levels[3]] * 0.1,
    }

    normalized: list[float] = []
    for name in ("eq1", "eq2", "eq3eq6", "eq4"):
        available = value - lower_scores[name]
        if math.isfinite(available) and available >= 0:
            normalized.append(available * distances[name] / max_severity[name])

    if normalized:
        value -= sum(normalized) / len(normalized)
    value = min(10.0, max(0.0, value))
    return _round_half_up_one_decimal(value)


def _macro_vector(values: Mapping[str, str]) -> str:
    eq1 = (
        0
        if values["AV"] == "N" and values["PR"] == "N" and values["UI"] == "N"
        else 1
        if (
            (values["AV"] == "N" or values["PR"] == "N" or values["UI"] == "N")
            and not (
                values["AV"] == "N" and values["PR"] == "N" and values["UI"] == "N"
            )
            and values["AV"] != "P"
        )
        else 2
    )
    eq2 = 0 if values["AC"] == "L" and values["AT"] == "N" else 1
    eq3 = (
        0
        if values["VC"] == "H" and values["VI"] == "H"
        else 1
        if values["VC"] == "H" or values["VI"] == "H" or values["VA"] == "H"
        else 2
    )
    eq4 = (
        0
        if values["SI"] == "S" or values["SA"] == "S"
        else 1
        if values["SC"] == "H" or values["SI"] == "H" or values["SA"] == "H"
        else 2
    )
    eq5 = {"A": 0, "P": 1, "U": 2}[values["E"]]
    eq6 = (
        0
        if (
            (values["CR"] == "H" and values["VC"] == "H")
            or (values["IR"] == "H" and values["VI"] == "H")
            or (values["AR"] == "H" and values["VA"] == "H")
        )
        else 1
    )
    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _lower_macro_scores(levels: tuple[int, ...]) -> dict[str, float]:
    eq1, eq2, eq3, eq4, eq5, eq6 = levels
    scores = {
        "eq1": CVSS_V40_LOOKUP.get(f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}", float("nan")),
        "eq2": CVSS_V40_LOOKUP.get(f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}", float("nan")),
        "eq4": CVSS_V40_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}", float("nan")),
    }
    if eq3 == 0 and eq6 == 0:
        left = CVSS_V40_LOOKUP.get(f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}", float("nan"))
        right = CVSS_V40_LOOKUP.get(f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}", float("nan"))
        scores["eq3eq6"] = max(left, right)
    elif eq3 == 1 and eq6 == 0:
        scores["eq3eq6"] = CVSS_V40_LOOKUP.get(
            f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}", float("nan")
        )
    elif (eq3, eq6) in ((0, 1), (1, 1)):
        scores["eq3eq6"] = CVSS_V40_LOOKUP.get(
            f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}", float("nan")
        )
    else:
        scores["eq3eq6"] = CVSS_V40_LOOKUP.get(
            f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}", float("nan")
        )
    return scores


def _max_vectors(levels: tuple[int, ...]) -> tuple[str, ...]:
    eq1, eq2, eq3, eq4, eq5, eq6 = levels
    return tuple(
        a + b + c + d + e
        for a in _EQ1_MAX[eq1]
        for b in _EQ2_MAX[eq2]
        for c in _EQ3_MAX[eq3][eq6]
        for d in _EQ4_MAX[eq4]
        for e in _EQ5_MAX[eq5]
    )


def _find_max_vector_distances(
    values: Mapping[str, str], max_vectors: tuple[str, ...]
) -> tuple[float, float, float, float]:
    for vector in max_vectors:
        candidate = _parse_metric_fragment(vector)
        all_distances = {
            "AV": _AV_LEVELS[values["AV"]] - _AV_LEVELS[candidate["AV"]],
            "PR": _PR_LEVELS[values["PR"]] - _PR_LEVELS[candidate["PR"]],
            "UI": _UI_LEVELS[values["UI"]] - _UI_LEVELS[candidate["UI"]],
            "AC": _AC_LEVELS[values["AC"]] - _AC_LEVELS[candidate["AC"]],
            "AT": _AT_LEVELS[values["AT"]] - _AT_LEVELS[candidate["AT"]],
            "VC": _VC_LEVELS[values["VC"]] - _VC_LEVELS[candidate["VC"]],
            "VI": _VI_LEVELS[values["VI"]] - _VI_LEVELS[candidate["VI"]],
            "VA": _VA_LEVELS[values["VA"]] - _VA_LEVELS[candidate["VA"]],
            "SC": _SC_LEVELS[values["SC"]] - _SC_LEVELS[candidate["SC"]],
            "SI": _SI_LEVELS[values["SI"]] - _SI_LEVELS[candidate["SI"]],
            "SA": _SA_LEVELS[values["SA"]] - _SA_LEVELS[candidate["SA"]],
            "CR": _CR_LEVELS[values["CR"]] - _CR_LEVELS[candidate["CR"]],
            "IR": _IR_LEVELS[values["IR"]] - _IR_LEVELS[candidate["IR"]],
            "AR": _AR_LEVELS[values["AR"]] - _AR_LEVELS[candidate["AR"]],
        }
        if any(value < 0 for value in all_distances.values()):
            continue
        return (
            all_distances["AV"] + all_distances["PR"] + all_distances["UI"],
            all_distances["AC"] + all_distances["AT"],
            all_distances["VC"]
            + all_distances["VI"]
            + all_distances["VA"]
            + all_distances["CR"]
            + all_distances["IR"]
            + all_distances["AR"],
            all_distances["SC"] + all_distances["SI"] + all_distances["SA"],
        )
    raise ValueError("CVSS v4.0 MacroVector has no valid maximum vector")


def _parse_metric_fragment(fragment: str) -> dict[str, str]:
    return {
        name: value
        for name, value in (part.split(":") for part in fragment.strip("/").split("/"))
    }


def _round_half_up_one_decimal(value: float) -> float:
    return float(
        Decimal(str(value + 1e-6)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    )
