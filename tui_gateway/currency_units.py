"""ISO 4217 minor units: how many decimals an amount in a currency has (EUR 2, JPY 0, KWD 3).

An ``amount`` form field is a decimal string; the contract (``contract/requests/README.md`` §4) allows at most
as many decimals as the currency's minor unit, so ``"1500.5"`` is no yen amount and ``"1.250"`` is no euro
amount. The table lists the active currency codes of ISO 4217 (funds codes with a minor unit included, the
precious-metal and testing codes, which have none, excluded). :func:`exponent` is None for a code it does not
list, so a caller decides whether that is a refusal (the form builder) or the usual two decimals (an answer check
for a frame the gateway built earlier).
"""

from __future__ import annotations

_ZERO = "BIF CLP DJF GNF ISK JPY KMF KRW PYG RWF UGX UYI VND VUV XAF XOF XPF"
_THREE = "BHD IQD JOD KWD LYD OMR TND"
_FOUR = "CLF UYW"
_TWO = (
    "AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BMD BND BOB BOV BRL BSD BTN BWP BYN BZD CAD CDF CHE "
    "CHF CHW CNY COP COU CRC CUP CVE CZK DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD GTQ GYD HKD HNL "
    "HTG HUF IDR ILS INR IRR JMD KES KGS KHR KPW KYD KZT LAK LBP LKR LRD LSL MAD MDL MGA MKD MMK MNT MOP MRU MUR "
    "MVR MWK MXN MXV MYR MZN NAD NGN NIO NOK NPR NZD PAB PEN PGK PHP PKR PLN QAR RON RSD RUB SAR SBD SCR SDG SEK "
    "SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TOP TRY TTD TWD TZS UAH USD USN UYU UZS VED VES WST XCD "
    "YER ZAR ZMW ZWG"
)

MINOR_UNITS: dict[str, int] = {
    **{code: 0 for code in _ZERO.split()},
    **{code: 2 for code in _TWO.split()},
    **{code: 3 for code in _THREE.split()},
    **{code: 4 for code in _FOUR.split()},
}

#: The most decimals any amount value may carry whatever the currency (the contract's ``FORM_DECIMAL``).
MAX_DECIMALS = 3
#: What an answer check assumes for a currency this table does not list.
DEFAULT_EXPONENT = 2


def exponent(currency: str) -> int | None:
    """The ISO 4217 minor-unit exponent of *currency*, or None for a code not listed."""
    return MINOR_UNITS.get(currency)
