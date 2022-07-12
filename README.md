# go-crypto-winnative

<!-- Add once the repostory has been pulled publicly.
[![Go Reference](https://pkg.go.dev/badge/github.com/microsoft/go-crypto-winnative/cng.svg)](https://pkg.go.dev/github.com/microsoft/go-crypto-winnative/cng)
-->

The `cng` package implements Go crypto primitives on Windows using [CNG](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal). When configured correctly, CNG can be executed in FIPS mode.

The `cng` package is designed to be used as a drop-in replacement for the [boring](https://pkg.go.dev/crypto/internal/boring) package in order to facilitate integrating `cng` inside a forked Go toolchain.

## Disclaimer

A program directly or indirectly using this package in FIPS mode can claim it is using a FIPS-certified cryptographic module (CNG), but it can't claim the program as a whole is FIPS certified without passing the certification process, nor claim it is FIPS compliant without ensuring all crypto APIs and workflows are implemented in a FIPS-compliant manner.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
