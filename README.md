# bwenv

`bwenv` resolves 1Password-style `op://` references from Bitwarden or
Vaultwarden through the official `bw` CLI. It is intended for local use and
macOS LaunchAgents, not CI.

## Install and configure

`bwenv.py` only requires Python 3. On a self-hosted instance, configure the
Bitwarden CLI once and authenticate interactively:

```sh
bw config server https://bitwarden-poc.kefapps.wtf
bw login
bw unlock
```

The CLI must be unlocked whenever `bwenv` resolves a reference. For a
LaunchAgent, save the resulting session in the logged-in user's macOS
Keychain:

```sh
python3 bwenv.py keychain set-session --service bwenv.bitwarden-poc.kefapps.wtf
python3 bwenv.py --keychain-service bwenv.bitwarden-poc.kefapps.wtf read \
  op://Infra/service/token
```

The stored session can expire or be revoked. Refresh it interactively with
`keychain set-session`; `bwenv` deliberately fails rather than prompting from
a background process.

## Reference resolution

The supported compatibility form is:

```text
op://<organisation>/<item>/<champ>
```

`bwenv` finds the exact Vaultwarden organisation, then the exact item name,
then an exact custom field. Custom fields take precedence over `username`,
`password`, `notes`, and `note`.

For migrations, an item may instead contain the original `op://organisation/item`
or full `op://organisation/item/champ` in a Bitwarden login URI. This URI
lookup is only used after direct lookup fails. Missing and ambiguous matches
always fail; no value is guessed.

The legacy `bw://organisation/item/champ` form remains available for simple
references. It is not the compatibility contract of this fork.

## Commands

```sh
# Print one value to stdout.
python3 bwenv.py read op://Infra/service/token

# Resolve environment variables whose entire value is op://... or bw://... .
TOKEN=op://Infra/service/token python3 bwenv.py run -- ./service

# Inject braced or bare op:// references from stdin to stdout.
printf 'token={{ op://Infra/service/token }}\n' | python3 bwenv.py inject

# Render a file atomically. Existing output requires --force when noninteractive.
python3 bwenv.py inject -i runtime.env.tpl -o runtime.env --file-mode 0600 --force
```

`inject` accepts `-i/--in-file`, `-o/--out-file`, `--file-mode`, and
`-f/--force`, matching the relevant `op inject` workflow. Output files are
created through a same-directory temporary file and atomically renamed; the
default mode is `0600`.

`run`, `read`, and `inject` accept `--keychain-service` before the command:

```sh
python3 bwenv.py --keychain-service bwenv.bitwarden-poc.kefapps.wtf run -- ./service
```

`BW_SESSION` is used only while `bwenv` queries `bw`; it is removed before the
child process starts. Diagnostics never include resolved values or `bw` stderr.

## Import a 1Password fallback export

The import command accepts the protected fallback JSON produced for the
1Password quota incident. It requires a regular file with mode `0600` (or
stricter), reads only `secrets`, and imports only valid `op://` entries. Entries
such as `OP_SERVICE_ACCOUNT_TOKEN` are excluded automatically.

Run the local, value-free dry-run first:

```sh
python3 bwenv.py import-1password-fallback \
  --file /Users/jbodin/messenger-connector-secrets-fallback.json
```

The dry-run does not invoke `bw` and prints only counts by organisation. To
apply, first create the target organizations and one existing collection in
each of them. `bwenv` does not create organizations or collections. It refuses
to overwrite an item with the same organization and name, and performs all
organization, collection, and collision checks before creating the first item.

```sh
python3 bwenv.py --keychain-service bwenv.bitwarden-poc.kefapps.wtf \
  import-1password-fallback \
  --file /Users/jbodin/messenger-connector-secrets-fallback.json \
  --apply \
  --collection Infra=Deployments \
  --collection 'Personal Ops=Deployments'
```

Each imported item stores every path field as a custom Bitwarden field, which
preserves the `op://organisation/item/champ` contract exactly. `--apply` is the
only command that sends a fallback value to Vaultwarden.

## LaunchAgents

Copy and adapt
[`launchd/com.bwenv.runtime.example.plist`](launchd/com.bwenv.runtime.example.plist).
It is a generic wrapper only: no existing service is changed by this project.

## Development

```sh
python3 -m unittest discover -v
python3 -m py_compile bwenv.py
```

## CI boundary

This tool never reads GitHub secrets or runs in GitHub Actions. Existing CI and
deployment automation remain backed by AWS Secrets Manager and OIDC.

## License and provenance

The upstream project is released under the [Unlicense](UNLICENSE). See
[`PROVENANCE.md`](PROVENANCE.md) for the pinned upstream revision and the
security changes made by this fork.
