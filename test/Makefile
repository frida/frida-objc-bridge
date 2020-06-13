RUNNER_ARGS ?=

IOS_HOST = iphone
IOS_ARCH = arm64
IOS_PREFIX = /usr/local/opt/frida-objc-bridge-tests-$(IOS_ARCH)

frida_version := 12.9.7

cflags := -Wall -pipe -Os -g
ldflags := -Wl,-framework,Foundation -lfrida-gumjs -lresolv -Wl,-dead_strip
toolchain := $(shell dirname $(shell dirname $(shell dirname $(shell xcrun --toolchain XcodeDefault -f swift))))

macos_cc := $(shell xcrun --sdk macosx -f clang)
macos_swift := $(shell xcrun --sdk macosx -f swift)
macos_sdk := $(shell xcrun --sdk macosx --show-sdk-path)
macos_cflags := -isysroot "$(macos_sdk)" -arch x86_64 $(cflags) -DHAVE_MACOS -DHAVE_V8
macos_runtimedir := $(toolchain)/usr/lib/swift-5.0/macosx
macos_swift_runtimedir := /usr/lib/swift
macos_ldflags := "-L$(macos_runtimedir)" -lswiftObjectiveC "-Wl,-rpath,$(macos_swift_runtimedir),-rpath,$(macos_runtimedir)" $(ldflags)

ios_cc := $(shell xcrun --sdk iphoneos -f clang)
ios_swift := $(shell xcrun --sdk iphoneos -f swift)
ios_sdk := $(shell xcrun --sdk iphoneos --show-sdk-path)
ios_cflags := -isysroot "$(ios_sdk)" -arch $(IOS_ARCH) -miphoneos-version-min=7.0 $(cflags) -DHAVE_IOS
ios_runtimedir := $(toolchain)/usr/lib/swift-5.0/iphoneos
ios_ldflags := "-L$(ios_runtimedir)" -lswiftObjectiveC "-Wl,-rpath,$(IOS_PREFIX)" $(ldflags)
ios_codesign := $(shell xcrun --sdk iphoneos -f codesign)
ios_swift_libraries := \
	$(ios_runtimedir)/libswiftCore.dylib \
	$(ios_runtimedir)/libswiftCoreFoundation.dylib \
	$(ios_runtimedir)/libswiftCoreGraphics.dylib \
	$(ios_runtimedir)/libswiftDarwin.dylib \
	$(ios_runtimedir)/libswiftDispatch.dylib \
	$(ios_runtimedir)/libswiftFoundation.dylib \
	$(ios_runtimedir)/libswiftObjectiveC.dylib \
	$(ios_runtimedir)/libswiftSwiftOnoneSupport.dylib \
	$(NULL)

objc_sources := runner.m basics.m
objc_headers := fixture.m
swift_sources := taylor.swift

js_sources := ../index.js

all: run-macos

clean:
	rm -rf build

build-macos: build/macos-x86_64/runner
build-ios: build/ios-$(IOS_ARCH)/runner

run-macos: build/macos-x86_64/runner build/frida-objc-bridge.js
	$< $(RUNNER_ARGS)
run-ios: build/ios-$(IOS_ARCH)/runner build/frida-objc-bridge.js build/ios-$(IOS_ARCH)/.swift-runtime-stamp
	cd build/ios-$(IOS_ARCH)/ && rsync -rLz runner ../frida-objc-bridge.js *.dylib "$(IOS_HOST):$(IOS_PREFIX)/"
	ssh $(IOS_HOST) "$(IOS_PREFIX)/runner $(RUNNER_ARGS)"

watch-macos: build/macos-x86_64/runner build/frida-objc-bridge.js
	npm run watch &
	./node_modules/.bin/chokidar \
		build/frida-objc-bridge.js \
		-c 'build/macos-x86_64/runner $(RUNNER_ARGS)'
watch-ios: build/ios-$(IOS_ARCH)/runner build/frida-objc-bridge.js
	npm run watch &
	./node_modules/.bin/chokidar \
		build/frida-objc-bridge.js \
		-c 'scp build/frida-objc-bridge.js "$(IOS_HOST):$(IOS_PREFIX)/" \
			&& ssh $(IOS_HOST) "$(IOS_PREFIX)/runner $(RUNNER_ARGS)"'

build/macos-x86_64/runner: $(objc_sources) $(objc_headers) build/macos-x86_64/taylor.o build/macos-x86_64/libfrida-gumjs.a
	"$(macos_cc)" \
		$(macos_cflags) \
		$(objc_sources) \
		build/macos-x86_64/taylor.o \
		-o $@ \
		-Ibuild/macos-x86_64 -Lbuild/macos-x86_64 \
		$(macos_ldflags)
build/ios-$(IOS_ARCH)/runner: $(objc_sources) $(objc_headers) build/ios-$(IOS_ARCH)/taylor.o runner.xcent build/ios-$(IOS_ARCH)/libfrida-gumjs.a
	"$(ios_cc)" \
		$(ios_cflags) \
		$(objc_sources) \
		build/ios-$(IOS_ARCH)/taylor.o \
		-o $@ \
		-Ibuild/ios-$(IOS_ARCH) -Lbuild/ios-$(IOS_ARCH) \
		$(ios_ldflags)
	"$(ios_codesign)" -f -s "$$IOS_CERTID" --entitlements runner.xcent $@

build/macos-x86_64/taylor.o: taylor.swift
	@mkdir -p $(@D)
	"$(macos_swift)" \
		-frontend \
		-c \
		-primary-file taylor.swift \
		-sdk "$(macos_sdk)" \
		-module-name FridaObjCTests \
		-emit-module-path build/macos-x86_64/FridaObjCTests.swiftmodule \
		-emit-objc-header-path build/macos-x86_64/taylor.h \
		-enable-testing \
		-enable-objc-interop \
		-parse-as-library \
		-o $@
build/ios-$(IOS_ARCH)/taylor.o: taylor.swift
	@mkdir -p $(@D)
	"$(ios_swift)" \
		-frontend \
		-c \
		-primary-file taylor.swift \
		-target $(IOS_ARCH)-apple-ios7.0-iphoneos \
		-sdk "$(ios_sdk)" \
		-module-name FridaObjCTests \
		-emit-module-path build/ios-$(IOS_ARCH)/FridaObjCTests.swiftmodule \
		-emit-objc-header-path build/ios-$(IOS_ARCH)/taylor.h \
		-enable-testing \
		-enable-objc-interop \
		-parse-as-library \
		-o $@

build/ios-$(IOS_ARCH)/.swift-runtime-stamp: $(ios_swift_libraries)
	@mkdir -p $(@D)
	cp $^ $(@D)
	"$(ios_codesign)" -f -s "$$IOS_CERTID" $(@D)/*.dylib
	@touch $@

build/%/libfrida-gumjs.a:
	@mkdir -p $(@D)
	curl -Ls https://github.com/frida/frida/releases/download/$(frida_version)/frida-gumjs-devkit-$(frida_version)-$*.tar.xz | tar -xJf - -C $(@D)

build/frida-objc-bridge.js: $(js_sources) node_modules
	npm run build

node_modules: package.json
	npm install

.PHONY: all clean build-macos build-ios run-macos run-ios watch-macos watch-ios
