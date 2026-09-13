# igNTP: package layout

The library package is `igntp`, under the same-named source directory. `Commons` contains types and shared contracts; `Features` contains protocol functionality. `Master` contains the runtime client or relay.

Import paths come from source `package` declarations. Do not insert `src` into an import path. Tests remain separate executable consumers of the library.

Both the library and its core test project use only the Cangjie standard library.
