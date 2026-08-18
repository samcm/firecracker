# CPU template helper tool

The `cpu-template-helper` tool is a program designed to assist users with
creating and managing their custom CPU templates.

## Usage

The `cpu-template-helper` tool has two sets of commands: template-related
commands and fingerprint-related commands.

### Template-related commands


#### Strip command

This command strips identical entries from multiple CPU template files.

```
cpu-template-helper template strip \
    --paths <cpu-config-1> <cpu-config-2> [..<cpu-config-N>] \
    --suffix <suffix>
```

One practical use case of the CPU template feature is to provide a consistent
CPU feature set to guests running on multiple CPU models. When creating a custom
CPU template for this purpose, it is efficient to focus on the differences in
guest CPU configurations across those CPU models. Given that a dumped guest CPU
configuration typically amounts to approximately 1,000 lines, this command
considerably narrows down the scope to consider.


### Fingerprint-related commands


#### Compare command

This command compares two fingerprint files: one was taken at the time of custom
CPU template creation and the other is taken currently.

```
cpu-template-helper fingerprint compare \
    --prev <prev-fingerprint> \
    --curr <curr-fingerprint> \
    --filters <field-1> [..<field-N>]
```

By continously comparing fingerprint files, users can ensure they are aware of
any changes that could require revising the custom CPU template. However, it is
worth noting that not all of these changes necessarily require a revision, and
some changes could be inconsequential to the custom CPU template depending on
its use case. To provide users with flexibility in comparing fingerprint files
based on situations or use cases, the `--filters` option allows users to select
which fields to compare.

As examples of when to compare fingerprint files:

- When bumping the Firecracker version up
- When bumping the kernel version up
- When applying a microcode update (or launching a new host (e.g. AWS EC2 metal
  instance))

