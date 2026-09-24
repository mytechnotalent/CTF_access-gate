# OPERATION COLD IRON - The Ten Acts and the Backbone

The spine of the saga. Every repository in the series carries this file so each
one stays standalone.

## THE WORLD

The Ministry runs the state. It watches the cities with TELESCREEN, and it runs
the machinery underneath them: the cold chain, the gates, the pipelines, the
grid, the water. Its industrial arm is a set of deniable fronts. The one in these
pages is NorthPharma, and its security contractor is FROSTLINE.

Against them is WHITEOUT, a resistance that does not exist on paper, and
NIGHTINGALE, the Ministry engineer who copied the first image and then went
silent.

The ten acts are the Ministry's industrial edge, on the RP2350. TELESCREEN is the
surveillance backbone on the RP5, and it comes after the ten.

## The acts

| Act | Codename | Project | Domain | New lesson |
| --- | -------- | ------- | ------ | ---------- |
| I | COLD IRON | cold-chain-monitor | cold chain | integrity: the lie, authenticated telemetry |
| II | IRON GATE | access-gate | access control | authority: replay, state integrity |
| III | IRON VEIN | pipeline-valve-controller | SCADA pipeline | the implant: logic bomb, beacon, anti-debug |
| IV | IRON LUNG | hvac-automation-node | HVAC | persistence: survives reflash |
| V | IRON WEB | industrial-tamper-system | chassis tamper | propagation: a worm over LoRa |
| VI | IRON COURIER | smart-logistics-dropbox | logistics | exfiltration: a covert channel |
| VII | IRON CHOIR | factory-andon-station | factory floor | command and control: botnet tasking |
| VIII | IRON VAULT | datacenter-vent-controller | datacenter | availability: lockout logic |
| IX | IRON FANG | smart-parking-barrier | smart city | physical weaponization |
| X | IRON CURTAIN | chemical-warning-terminal | chemical storage | the finale: coordinated incident response |

## The backbone (post-ten)

| Codename | Project | Domain | Lesson |
| -------- | ------- | ------ | ------ |
| TELESCREEN | telescreen | RP5 surveillance backbone | the Ministry's own network, after the ten acts |

## The two tracks

- **Fix track.** Find and repair the device's vulnerabilities. Every act has one.
- **Malware track.** Analyze and neutralize a benign implant. Acts I and II are
  intentionally vulnerability-only; the malware track begins at Act III.

## The safety contract (Acts III-X)

The malware is real in technique and harmless in effect.

- No network, no internet, no host impact. The target is bare-metal RP2350
  firmware with no operating system and no filesystem.
- Effects are confined to GPIO: a servo, LEDs, and an LCD on your own breadboard.
- Synthetic data only. Nothing real is exfiltrated.
- A `SANDBOX_ONLY` build guard disables risky paths, and the tests assert that the
  implant cannot act outside its reserved flash sector or its own pins.
- Every act ends in analysis and neutralization.

## Repositories

Each act has a project repository (the defended device) and a companion CTF
repository (the compromised artifact). Read them in order.

| Act | Project | CTF |
| --- | ------- | --- |
| I | [cold-chain-monitor](https://github.com/mytechnotalent/cold-chain-monitor) | [CTF_cold-chain-monitor](https://github.com/mytechnotalent/CTF_cold-chain-monitor) |
| II | [access-gate](https://github.com/mytechnotalent/access-gate) | [CTF_access-gate](https://github.com/mytechnotalent/CTF_access-gate) |
| III | [pipeline-valve-controller](https://github.com/mytechnotalent/pipeline-valve-controller) | [CTF_pipeline-valve-controller](https://github.com/mytechnotalent/CTF_pipeline-valve-controller) |
| IV | [hvac-automation-node](https://github.com/mytechnotalent/hvac-automation-node) | [CTF_hvac-automation-node](https://github.com/mytechnotalent/CTF_hvac-automation-node) |
| V | [industrial-tamper-system](https://github.com/mytechnotalent/industrial-tamper-system) | [CTF_industrial-tamper-system](https://github.com/mytechnotalent/CTF_industrial-tamper-system) |
| VI | [smart-logistics-dropbox](https://github.com/mytechnotalent/smart-logistics-dropbox) | [CTF_smart-logistics-dropbox](https://github.com/mytechnotalent/CTF_smart-logistics-dropbox) |
| VII | [factory-andon-station](https://github.com/mytechnotalent/factory-andon-station) | [CTF_factory-andon-station](https://github.com/mytechnotalent/CTF_factory-andon-station) |
| VIII | [datacenter-vent-controller](https://github.com/mytechnotalent/datacenter-vent-controller) | [CTF_datacenter-vent-controller](https://github.com/mytechnotalent/CTF_datacenter-vent-controller) |
| IX | [smart-parking-barrier](https://github.com/mytechnotalent/smart-parking-barrier) | [CTF_smart-parking-barrier](https://github.com/mytechnotalent/CTF_smart-parking-barrier) |
| X | [chemical-warning-terminal](https://github.com/mytechnotalent/chemical-warning-terminal) | [CTF_chemical-warning-terminal](https://github.com/mytechnotalent/CTF_chemical-warning-terminal) |
| Backbone | [telescreen](https://github.com/mytechnotalent/telescreen) | [CTF_telescreen](https://github.com/mytechnotalent/CTF_telescreen) |

## The chain

Every README links forward: each project links to its own CTF, each CTF links to
the next act's project, and the final act (X) CTF links to the TELESCREEN
backbone.
