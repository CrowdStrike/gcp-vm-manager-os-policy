# Run `cs-policy` in Google Cloud Shell

Google Cloud Shell includes the Google Cloud CLI and uses the account you
authorized for the current Cloud Shell session. You do not need to run
`gcloud auth application-default login`; Google does not support that command in
Cloud Shell. The first command that accesses a Google Cloud API may instead ask
you to authorize Cloud Shell in the browser.

Before you begin, make sure your account has permission to enable services,
upload objects to the target Cloud Storage bucket, and create OS policy
assignments. You also need a CrowdStrike API client with the `Sensor Download`
read scope.

## Select the project and prepare a bucket

Open Cloud Shell from the Google Cloud console, then select the project that
will contain the OS policy assignments:

```shell
gcloud config set project PROJECT_ID
gcloud config get-value project
```

Enable the APIs used by `cs-policy`:

```shell
gcloud services enable \
  compute.googleapis.com \
  osconfig.googleapis.com \
  storage.googleapis.com
```

The tool uploads Falcon sensor packages to an existing Cloud Storage bucket.
If you do not already have one, create a bucket with a globally unique name:

```shell
bucket_name="YOUR_GLOBALLY_UNIQUE_BUCKET_NAME"
gcloud storage buckets create "gs://${bucket_name}" \
  --location=us-central1 \
  --uniform-bucket-level-access
```

Choose a bucket location that meets your organization's requirements.

## Install the latest release

The following commands detect the Cloud Shell architecture, download the latest
published release, verify its checksum, and install the binary in your
persistent Cloud Shell home directory:

```shell
release_tag="$(curl -fsSL https://api.github.com/repos/CrowdStrike/gcp-vm-manager-os-policy/releases/latest \
  | awk -F'"' '/"tag_name":/ { print $4; exit }')"
release_version="${release_tag#v}"

case "$(uname -m)" in
  x86_64) release_arch="x86_64" ;;
  aarch64|arm64) release_arch="arm64" ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

archive="cs-policy_Linux_${release_arch}.tar.gz"
checksums="cs-policy_${release_version}_checksums.txt"
release_url="https://github.com/CrowdStrike/gcp-vm-manager-os-policy/releases/download/${release_tag}"

curl -fLO "${release_url}/${archive}"
curl -fLO "${release_url}/${checksums}"
grep "  ${archive}$" "${checksums}" | sha256sum --check -

install -d "$HOME/.local/bin"
tar -xzf "${archive}" -C "$HOME/.local/bin" cs-policy
export PATH="$HOME/.local/bin:$PATH"

cs-policy --help
```

## Provide CrowdStrike credentials

Read the API client values without placing the secret directly in your shell
history. Replace `us-1` if your tenant uses another Falcon cloud:

```shell
read -r -p "Falcon API client ID: " FALCON_CLIENT_ID
read -r -s -p "Falcon API client secret: " FALCON_CLIENT_SECRET
printf '\n'
export FALCON_CLIENT_ID FALCON_CLIENT_SECRET
export FALCON_CLOUD="us-1"
```

## Create the OS policy assignments

Pass the bucket name and one or more target zones. The command downloads the
supported sensor packages, uploads them to the bucket, writes policy files in
the current directory, and creates an assignment in each requested zone.

```shell
cs-policy create \
  --bucket="${bucket_name}" \
  --zones="us-central1-a,us-central1-b"
```

Use `cs-policy create --help` to review optional install parameters, the output
directory, and rollout waiting behavior.

Remove the CrowdStrike credentials from the shell when the command finishes:

```shell
unset FALCON_CLIENT_ID FALCON_CLIENT_SECRET FALCON_CLOUD
```

For details about Cloud Shell authorization and Application Default
Credentials, see Google's documentation for
[authorizing Cloud Shell](https://cloud.google.com/shell/docs/auth) and
[cloud-based development environments](https://cloud.google.com/docs/authentication/set-up-adc-cloud-dev-environment).
