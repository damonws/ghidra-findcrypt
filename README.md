# Ghidra FindCrypt

Find cryptographic constants with Ghidra.

## Building

| Branch            | Ghidra Versions |
| ----------------- | --------------- |
| `main`            | latest          |
| `min_ghidra_11_0` | 11.0 to 11.3.2  |
| `min_ghidra_11_4` | 11.4 to latest  |

```shell
gradle -PGHIDRA_INSTALL_DIR="<ghidra-install-dir>"
```

## Installing

Follow the instructions in the Extensions section of Ghidra's GettingStarted
document.

## Using

Once the script is installed, a new Analysis is added to the Auto Analyze window
called "Find Crypt", it's enabled by default and it's safe to re-run. If you have
an existing file, open the "Analysis" menu in the CodeBrowser tool and click
"Auto Analyze". Select the "Find Crypt" analysis from the list and click Analyze.

Once the analysis is complete, any found crypt constants will be labeled with
the algorithm they're associated with. You can find these labels in the "Labels"
folder in the Symbol Tree window. The labels are prefixed with `CRYPT_` to group
them together.

The analysis will also try to set the datatype for the found constants, but if
a datatype has been applied by another analysis module that other module will
take precedence.

A comment is always placed when a crypt constant is found to tell you the type
and the size of the constant, just in case the datatype wasn't applied.
