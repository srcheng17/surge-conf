# surge-conf

Personal Surge rule sets maintained for direct use from GitHub Raw URLs.

## Filtered AIGC rules

`surge/rules/AIGC-filtered.list` tracks the upstream
[`Rabbit-Spec/Surge` AIGC rules](https://github.com/Rabbit-Spec/Surge/blob/Master/Rules/AIGC.list)
while removing these overly broad network rules:

- `IP-ASN,13335,no-resolve` (Cloudflare)
- `IP-ASN,20473,no-resolve` (Vultr/The Constant Company)

The exclusions prevent unrelated sites on those shared networks from being
routed through the AIGC policy. Exact service domains, Anthropic's AS399358,
and the upstream CIDR rules remain intact.

GitHub Actions checks upstream at minute 17 of every hour. The updater validates
the source, regenerates deterministically, and commits only when the rule body
changes. It can also be run manually from the Actions page.

Use this rule in a Surge profile. The one-hour client interval matches the
GitHub update cadence:

```text
RULE-SET,https://raw.githubusercontent.com/srcheng17/surge-conf/main/surge/rules/AIGC-filtered.list,AIGC,update-interval=3600
```

Run the validation locally with:

```bash
node --test test/update-aigc-filtered.test.mjs
node scripts/update-aigc-filtered.mjs
```
