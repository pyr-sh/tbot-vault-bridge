# tbot-vault-bridge

An overcomplicated solution to a very niche problem.

`vault-pusher` is an API, authenticated using JWT, intended to allow for remote
pushes to Vault. Our Vault is protected by Teleport, a different one from the
one we intend to use this project with, so we would need to run a separate
`tbot` to permit machine access to the Vault Teleport.

`tbot-monitor` watches the contents of a directory and sends all writes to
`vault-pusher`. It's intended to keep the source directory and target Vault
keys in sync. It does not clean up after itself if files are removed. Changes
are debounced.
