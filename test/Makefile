IOS_HOST = iphone
IOS_ARCH = arm64
IOS_PREFIX = /usr/local/opt/frida-objc-tests-$(IOS_ARCH)

frida_version := 12.3.3

cflags := -Wall -pipe -Os -g
ldflags :=  -Wl,-framework,Foundation -lfrida-gumjs -lresolv -Wl,-dead_strip

macos_cc := $(shell xcrun --sdk macosx -f clang)
macos_sysroot := $(shell xcrun --sdk macosx --show-sdk-path)
macos_cflags := -isysroot "$(macos_sysroot)" -arch x86_64 -mmacosx-version-min=10.9 $(cflags) -DHAVE_MACOS
macos_ldflags := $(ldflags)

ios_cc := $(shell xcrun --sdk iphoneos -f clang)
ios_sysroot := $(shell xcrun --sdk iphoneos --show-sdk-path)
ios_cflags := -isysroot "$(ios_sysroot)" -arch $(IOS_ARCH) -miphoneos-version-min=7.0 $(cflags) -DHAVE_IOS
ios_ldflags := $(ldflags)
ios_codesign := $(shell xcrun --sdk iphoneos -f codesign)

sources := runner.m basics.m
headers := fixture.m

js_sources := ../index.js

all: run-macos

clean:
	rm -rf build

build-macos: build/macos-x86_64/runner
build-ios: build/ios-$(IOS_ARCH)/runner

run-macos: build/macos-x86_64/runner build/frida-objc.js
	$<
run-ios: build/ios-$(IOS_ARCH)/runner build/frida-objc.js
	ssh $(IOS_HOST) "rm -rf $(IOS_PREFIX); mkdir -p $(IOS_PREFIX)"
	scp $^ "$(IOS_HOST):$(IOS_PREFIX)/"
	ssh $(IOS_HOST) "$(IOS_PREFIX)/runner"

watch-macos: build/macos-x86_64/runner build/frida-objc.js
	npm run watch &
	./node_modules/.bin/chokidar \
		build/frida-objc.js \
		-c 'build/macos-x86_64/runner'
watch-ios: build/ios-$(IOS_ARCH)/runner build/frida-objc.js
	npm run watch &
	./node_modules/.bin/chokidar \
		build/frida-objc.js \
		-c 'scp build/frida-objc.js "$(IOS_HOST):$(IOS_PREFIX)/" \
			&& ssh $(IOS_HOST) "$(IOS_PREFIX)/runner"'

build/macos-x86_64/runner: $(sources) $(headers) build/macos-x86_64/libfrida-gumjs.a
	"$(macos_cc)" $(macos_cflags) \
		$(sources) \
		-o $@ \
		-Ibuild/macos-x86_64 -Lbuild/macos-x86_64 \
		$(macos_ldflags)
build/ios-$(IOS_ARCH)/runner: $(sources) $(headers) runner.xcent build/ios-$(IOS_ARCH)/libfrida-gumjs.a
	"$(ios_cc)" $(ios_cflags) \
		$(sources) \
		-o $@ \
		-Ibuild/ios-$(IOS_ARCH) -Lbuild/ios-$(IOS_ARCH) \
		$(ios_ldflags)
	"$(ios_codesign)" -f -s "$$IOS_CERTID" --entitlements runner.xcent $@

build/%/libfrida-gumjs.a:
	@mkdir -p $(@D)
	curl -Ls https://github.com/frida/frida/releases/download/$(frida_version)/frida-gumjs-devkit-$(frida_version)-$*.tar.xz | tar -xJf - -C $(@D)

build/frida-objc.js: $(js_sources) node_modules
	npm run build

node_modules: package.json
	npm install

.PHONY: all clean build-macos build-ios run-macos run-ios watch-macos watch-ios
