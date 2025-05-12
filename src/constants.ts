export const VERSION = "0.7.1";
export const DEFAULT_TIMEOUT = {
  connectionTimeout: 3050, // 3.05s in ms
  requestTimeout: 27000, // 27s in ms
};

export interface HashDictionary {
  [domain: string]: string[];
}

export const PUBKEY_HASH_DICT: HashDictionary = {
  "api.protonvpn.ch": [
    "drtmcR2kFkM8qJClsuWgUzxgBkePfRCkRpqUesyDmeE=",
    "YRGlaY0jyJ4Jw2/4M8FIftwbDIQfh8Sdro96CeEel54=",
    "AfMENBVvOS8MnISprtvyPsjKlPooqh8nMB/pvCrpJpw=",
  ],
  "protonvpn.com": [
    "8joiNBdqaYiQpKskgtkJsqRxF7zN0C0aqfi8DacknnI=",
    "JMI8yrbc6jB1FYGyyWRLFTmDNgIszrNEMGlgy972e7w=",
    "Iu44zU84EOCZ9vx/vz67/MRVrxF1IO4i4NIa8ETwiIY=",
  ],
};

export const ALT_HASH_DICT: HashDictionary = {
  backup: [
    "EU6TS9MO0L/GsDHvVc9D5fChYLNy5JdGYpJw0ccgetM=",
    "iKPIHPnDNqdkvOnTClQ8zQAIKG0XavaPkcEo0LBAABA=",
    "MSlVrBCdL0hKyczvgYVSRNm88RicyY04Q2y5qrBt0xA=",
    "C2UxW0T1Ckl9s+8cXfjXxlEqwAfPM4HiW2y3UdtBeCw=",
  ],
};

export const DNS_HOSTS: string[] = [
  "https://dns11.quad9.net/dns-query",
  "https://dns.google/dns-query",
];

export const ENCODED_URLS: string[] = [
  "dMFYGSLTQOJXXI33OOZYG4LTDNA.protonpro.xyz",
  "dMFYGSLTQOJXXI33ONVQWS3BOMNUA.protonpro.xyz",
];

export const SRP_MODULUS_PUBLIC_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----`;

export const SRP_MODULUS_KEY_FINGERPRINT = "248097092b458509c508dac0350585c4e9518f26";
