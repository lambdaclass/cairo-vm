# Release Process
- [ ] Pull latest from `main` branch.
- [ ] Determine release version string dependending on whether changes included
      in changelog are API breaking, it's a release candidate, etc.
- [ ] Checkout branch named `release-N` where N is the version string.
- [ ] Update the version field in the package entry of `Cargo.toml` files.
  - The versions must be the same.
  - There are 4 relevant `Cargo.toml` files in the repo:
    - `Cargo.toml`: update the version string.
    - `cairo-vm-cli/Cargo.toml`: update the version string and also the `cairo-vm` dependency version to match the above.
    - `felt/Cargo.toml`: update the version string.
    - `deps/parse-hyperlinks/Cargo.toml`: this vendored dependency needs its version bumped, but does not need to match the other crate versions.
  - [Here](https://github.com/lambdaclass/cairo-rs/pull/948/files) is an example pull request with these changes.
- Update `CHANGELOG.md`:
  - Verify that the changelog is up to date.
  - Add a title with the release version string just below the `Upcoming Changes` section.
- [ ] Commit your changes and push your branch, and create a Pull Request.
- [ ] Merge after CI and review passes.
- [ ] Pull latest from `main` again.
- [ ] Tag commit with version string and push tag.
- [ ] Watch the `publish` workflow run in Github Actions.
- [ ] Verify all the crates are available on crates.io with the correct versions.
- [ ] Announce release through corresponding channels.

