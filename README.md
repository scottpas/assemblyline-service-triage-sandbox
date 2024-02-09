# Triage Sandbox
This service uses [Triage Sandbox](https://tria.ge) to query and analyse submissions, returning Triage signatures, malware configs, and network information (with optional PCAP data).

## Service Config Variables
- `root_url` - The API URL to use (https://api.tria.ge, https://private.tria.ge/api, etc.)
- `api_key` - Sets a service-wide API key.
- `allow_dynamic_submit` - Allow dynamic submission of files. This overrides the submission parameter.

## Submission Parameters
- `analysis_timeout_in_seconds` - Sets the analysis time.
- `network` - Sets the network type to be used for analysis. These are the available options:
    - `internet` - Internet enabled
    - `drop` - Internet disabled
    - `tor` - Tor network
    - `sim200` - Simulate with HTTP 200 responses
    - `sim404` - Simulate with HTTP 404 responses
    - `simnx` - Simulate failing DNS
- `api_key` - A submission-level API key. This overrides the service-configured key.
- `use_existing_submission` - If this is true, the service searches for and uses the latest result from Triage.
- `extract_pcap` - Adds the PCAP for each task as an extracted file for futher analysis by services.
- `extract_memdump` - **To be implemented** - Adds memdump files for each task for further analysis by services.
- `allow_dynamic_submit` - If the service config allows dynamic submission, this will submit the sample to Triage.
- `submit_as_url` - Submits the request URI to Triage for analysis.

## Container Variables
- `MAX_ANALYSIS_TIMEOUT` - Sets the max timeout to wait for analysis to finish. This should be longer than the analysis timeout in the submission parameters to allow time for Triage to upload results. (Default: 600 seconds)
