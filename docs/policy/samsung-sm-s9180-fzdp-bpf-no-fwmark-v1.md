# Samsung SM-S9180 FZDP BPF no-fwmark review v1

## Assurance boundary

This is a lower-assurance `ExactArtifactObservedBehavior` review. It is selected only with reviewed
policy entry `samsung-sm-s9180-fzdp-observed-behavior-v1`; it is not source authentication and is
not transferable to another device policy, kernel build, translated byte stream, program type, or
tag.

The review used read-only `BPF_OBJ_GET_INFO_BY_FD` observations. Raw verifier-translated instruction
bytes reconstructed independently from opcode JSON produced the same SHA-256 values. Attached
cgroup programs also exposed BTF line information with no `mark` token. Exact instruction review
found no fwmark access in the listed cgroup and socket-filter artifacts. Because translated context
offsets and helper rewrites are device-private implementation details, only the complete exact
fingerprints below receive the exception.

## Runtime contract

- The fingerprint is `program-type | 8-byte tag | SHA-256(raw translated instructions)`.
- Every loaded program and BPF link is bracketed before and after inspection while obtained file
  descriptors remain open.
- `sched_cls` and `sched_act` are detached only when the TC filter dump is empty and no BPF link
  references the program. `netfilter` is detached only when no BPF link references it.
- An unknown policy, program type, link type, fingerprint, inaccessible object, invalid link
  reference, or snapshot drift remains opaque or fails collection.
- Program IDs, names, pin paths, link IDs, raw instructions, and device identity values are not
  catalog keys and are not retained by this artifact.

## Reviewed fingerprints

```text
cgroup_skb|40e069329ba49e7d|c8ef87e2d8d861b637b2cb53f8eefdfdec40fcec75a023350634d1898b416aa9
cgroup_skb|e0779ea72e69433a|06d8122f41450bc130f1e5fad149d55fd3f6df917d2ec6219956295a5f292e53
cgroup_sock|cea87e3ec965b36a|26e1be56d4c24d3dde7e8f6b60e991385886359d41b45fc83cca9936b1e1a9a1
cgroup_sock|f29419b678cbdebf|e383a1ac1f056a8d43e867a21b80b7b1cb669ec3ceaf4bd7ad7239f77dc0c5b8
cgroup_sock_addr|11d3e712279be333|2aecaddd37222eddfe32166323916562ca83c9dab8dcc438f64a50c72dada970
cgroup_sock_addr|57cd311f2e27366b|b11459a0e11ca14cbaa33cc108ffff8ff07ba54b6c389514b3c122ab54b34551
cgroup_sockopt|08d88dc82eb557d3|f4d484d3b95a1f215548bd2f7a9b39c6f1f81d65acb0d082313cbeafd67bd660
cgroup_sockopt|6710908637052bf9|4ca61c8d16cfe14cd073008e0c6d0881893504b01251b9a1cb4b0cf22b0f9942
socket_filter|31644e2c3ced33bd|58c935eec53f4faf59837d7761ceb6da1959c412b6c2660491f89c35cb2964dd
socket_filter|48d358c1b05b407f|ab2f33fbb6efcc9c45e7b9e269e92c7bb4676de1de59b19e4b0ea345c75ca198
socket_filter|5b66a4f866f45c5f|6f75333462ac1dc2b5c3990164d55aa58647fd5fb18e5d2a165524908bb0cfba
socket_filter|80d88f4843641ecd|52b3cfd923720b566711210a8d9a884c9b848ffbef0e50068b676583990f67f8
socket_filter|9951c9549a5ee17a|3e32a087abe42cf1ef90cb4e3103a6568c99c0c71894ee775a1d57c6f9e9bda2
socket_filter|a949fa08ab16ff6c|2d9d7aa5ba85a6c0ee3f70f34e8b3ec4dbdeed22747bc79e5b084a4d76809b27
socket_filter|ac07339589cf4481|cabd30c765774b56930eacc080695b95929c304d17ae2ddef81cf060d633ffd0
socket_filter|be318b3c229f7498|57d076cf5f956aa5b19c4ec5a844de6dd867aa362a3afecbcc33142f1a029f45
socket_filter|e991db169b5517fd|d351fbfdda1aadc45ed91843d5478116c62f5d81fbfe98e1ca2790c2c9a14fab
socket_filter|f20113889914f45a|4ea5cc8b5a342e3fd80086251034da296110dfeb0e6c234e2ebcc180e36d6c2c
socket_filter|f996e37eaee10540|c97d9312b287b518e9c411f3758a43ec652e36a1b17cb8ccdd02802f5fdead25
```
