# Kubenav Bindings

The kubenav bindings are used to make the request against the Kubernetes API from an iOS or Android device. The bindings are used in the [kubenav](https://github.com/kubenav/kubenav) app via the [Kubenav Plugin](https://github.com/kubenav/kubenav-plugin). The `.framework` and `.aar` files are generated via [Go mobile](https://github.com/golang/go/wiki/Mobile).

## Usage

Go modules support for `gomobile` and `gobind` is currently a work-in-progress (see [https://golang.org/issues/27234](https://github.com/golang/go/issues/27234)), therefor you must clone the repository into your `GOPATH`:

```sh
git clone git@github.com:kubenav/bind.git $GOPATH/src/github.com/kubenav/bind
cd $GOPATH/src/github.com/kubenav/bind
```

Install the required dependencies to generate the bindings (`gomobile`):

```sh
make dependencies
```

Create the `.framework` and `.aar` files which can then be used in the iOS/Android project:

```sh
gomobile init

make bindings-android
make bindings-ios
```
