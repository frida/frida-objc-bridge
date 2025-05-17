/* jshint esnext: true, evil: true */

import {getApi, defaultInvocationOptions} from './lib/api.js';
import * as fastpaths from './lib/fastpaths.js';

function Runtime() {
    const pointerSize = Process.pointerSize;
    let api = null;
    let apiError = null;
    const realizedClasses = new Set();
    const classRegistry = new ClassRegistry();
    const protocolRegistry = new ProtocolRegistry();
    const replacedMethods = new Map();
    const scheduledWork = new Map();
    let nextId = 1;
    let workCallback = null;
    let NSAutoreleasePool = null;
    const bindings = new Map();
    let readObjectIsa = null;
    const msgSendBySignatureId = new Map();
    const msgSendSuperBySignatureId = new Map();
    let cachedNSString = null;
    let cachedNSStringCtor = null;
    let cachedNSNumber = null;
    let cachedNSNumberCtor = null;
    let singularTypeById = null;
    let modifiers = null;

    try {
        tryInitialize();
    } catch (e) {
    }

    function tryInitialize() {
        if (api !== null)
            return true;

        if (apiError !== null)
            throw apiError;

        try {
            api = getApi();
        } catch (e) {
            apiError = e;
            throw e;
        }

        return api !== null;
    }

    function dispose() {
        for (const [rawMethodHandle, impls] of replacedMethods.entries()) {
            const methodHandle = ptr(rawMethodHandle);
            const [oldImp, newImp] = impls;
            if (api.method_getImplementation(methodHandle).equals(newImp))
                api.method_setImplementation(methodHandle, oldImp);
        }
        replacedMethods.clear();
    }

    Script.bindWeak(this, dispose);

    Object.defineProperty(this, 'available', {
        enumerable: true,
        get() {
            return tryInitialize();
        }
    });

    Object.defineProperty(this, 'api', {
        enumerable: true,
        get() {
          return getApi();
        }
    });

    Object.defineProperty(this, 'classes', {
        enumerable: true,
        value: classRegistry
    });

    Object.defineProperty(this, 'protocols', {
        enumerable: true,
        value: protocolRegistry
    });

    Object.defineProperty(this, 'Object', {
        enumerable: true,
        value: ObjCObject
    });

    Object.defineProperty(this, 'Protocol', {
        enumerable: true,
        value: ObjCProtocol
    });

    Object.defineProperty(this, 'Block', {
        enumerable: true,
        value: Block
    });

    Object.defineProperty(this, 'mainQueue', {
        enumerable: true,
        get() {
            return api?._dispatch_main_q ?? null;
        }
    });

    Object.defineProperty(this, 'registerProxy', {
        enumerable: true,
        value: registerProxy
    });

    Object.defineProperty(this, 'registerClass', {
        enumerable: true,
        value: registerClass
    });

    Object.defineProperty(this, 'registerProtocol', {
        enumerable: true,
        value: registerProtocol
    });

    Object.defineProperty(this, 'bind', {
        enumerable: true,
        value: bind
    });

    Object.defineProperty(this, 'unbind', {
        enumerable: true,
        value: unbind
    });

    Object.defineProperty(this, 'getBoundData', {
        enumerable: true,
        value: getBoundData
    });

    Object.defineProperty(this, 'enumerateLoadedClasses', {
        enumerable: true,
        value: enumerateLoadedClasses
    });

    Object.defineProperty(this, 'enumerateLoadedClassesSync', {
        enumerable: true,
        value: enumerateLoadedClassesSync
    });

    Object.defineProperty(this, 'choose', {
        enumerable: true,
        value: choose
    });

    Object.defineProperty(this, 'chooseSync', {
        enumerable: true,
        value(specifier) {
            const instances = [];
            choose(specifier, {
                onMatch(i) {
                    instances.push(i);
                },
                onComplete() {
                }
            });
            return instances;
        }
    });

    this.schedule = function (queue, work) {
        const id = ptr(nextId++);
        scheduledWork.set(id.toString(), work);

        if (workCallback === null) {
            workCallback = new NativeCallback(performScheduledWorkItem, 'void', ['pointer']);
        }

        Script.pin();
        api.dispatch_async_f(queue, id, workCallback);
    };

    function performScheduledWorkItem(rawId) {
        const id = rawId.toString();
        const work = scheduledWork.get(id);
        scheduledWork.delete(id);

        if (NSAutoreleasePool === null)
            NSAutoreleasePool = classRegistry.NSAutoreleasePool;

        const pool = NSAutoreleasePool.alloc().init();
        let pendingException = null;
        try {
            work();
        } catch (e) {
            pendingException = e;
        }
        pool.release();

        setImmediate(performScheduledWorkCleanup, pendingException);
    }

    function performScheduledWorkCleanup(pendingException) {
        Script.unpin();

        if (pendingException !== null) {
            throw pendingException;
        }
    }

    this.implement = function (method, fn) {
        return new NativeCallback(fn, method.returnType, method.argumentTypes);
    };

    this.selector = selector;

    this.selectorAsString = selectorAsString;

    function selector(name) {
        return api.sel_registerName(Memory.allocUtf8String(name));
    }

    function selectorAsString(sel) {
        return api.sel_getName(sel).readUtf8String();
    }

    const registryBuiltins = new Set([
        "prototype",
        "constructor",
        "hasOwnProperty",
        "toJSON",
        "toString",
        "valueOf"
    ]);

    function ClassRegistry() {
        const cachedClasses = {};
        let numCachedClasses = 0;

        const registry = new Proxy(this, {
            has(target, property) {
                return hasProperty(property);
            },
            get(target, property, receiver) {
                switch (property) {
                    case "prototype":
                        return target.prototype;
                    case "constructor":
                        return target.constructor;
                    case "hasOwnProperty":
                        return hasProperty;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                        return toString;
                    case "valueOf":
                        return valueOf;
                    default:
                        const klass = findClass(property);
                        return (klass !== null) ? klass : undefined;
                }
            },
            set(target, property, value, receiver) {
                return false;
            },
            ownKeys(target) {
                if (api === null)
                    return [];
                let numClasses = api.objc_getClassList(NULL, 0);
                if (numClasses !== numCachedClasses) {
                    // It's impossible to unregister classes in ObjC, so if the number of
                    // classes hasn't changed, we can assume that the list is up to date.
                    const classHandles = Memory.alloc(numClasses * pointerSize);
                    numClasses = api.objc_getClassList(classHandles, numClasses);
                    for (let i = 0; i !== numClasses; i++) {
                        const handle = classHandles.add(i * pointerSize).readPointer();
                        const name = api.class_getName(handle).readUtf8String();
                        cachedClasses[name] = handle;
                    }
                    numCachedClasses = numClasses;
                }
                return Object.keys(cachedClasses);
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: false,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        function hasProperty(name) {
            if (registryBuiltins.has(name))
                return true;
            return findClass(name) !== null;
        }

        function getClass(name) {
            const cls = findClass(name);
            if (cls === null)
                throw new Error("Unable to find class '" + name + "'");
            return cls;
        }

        function findClass(name) {
            let handle = cachedClasses[name];
            if (handle === undefined) {
                handle = api.objc_lookUpClass(Memory.allocUtf8String(name));
                if (handle.isNull())
                    return null;
                cachedClasses[name] = handle;
                numCachedClasses++;
            }

            return new ObjCObject(handle, undefined, true);
        }

        function toJSON() {
            return Object.keys(registry).reduce(function (r, name) {
                r[name] = getClass(name).toJSON();
                return r;
            }, {});
        }

        function toString() {
            return "ClassRegistry";
        }

        function valueOf() {
            return "ClassRegistry";
        }

        return registry;
    }

    function ProtocolRegistry() {
        let cachedProtocols = {};
        let numCachedProtocols = 0;

        const registry = new Proxy(this, {
            has(target, property) {
                return hasProperty(property);
            },
            get(target, property, receiver) {
                switch (property) {
                    case "prototype":
                        return target.prototype;
                    case "constructor":
                        return target.constructor;
                    case "hasOwnProperty":
                        return hasProperty;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                        return toString;
                    case "valueOf":
                        return valueOf;
                    default:
                        const proto = findProtocol(property);
                        return (proto !== null) ? proto : undefined;
                }
            },
            set(target, property, value, receiver) {
                return false;
            },
            ownKeys(target) {
                if (api === null)
                    return [];
                const numProtocolsBuf = Memory.alloc(pointerSize);
                const protocolHandles = api.objc_copyProtocolList(numProtocolsBuf);
                try {
                    const numProtocols = numProtocolsBuf.readUInt();
                    if (numProtocols !== numCachedProtocols) {
                        cachedProtocols = {};
                        for (let i = 0; i !== numProtocols; i++) {
                            const handle = protocolHandles.add(i * pointerSize).readPointer();
                            const name = api.protocol_getName(handle).readUtf8String();

                            cachedProtocols[name] = handle;
                        }
                        numCachedProtocols = numProtocols;
                    }
                } finally {
                    api.free(protocolHandles);
                }
                return Object.keys(cachedProtocols);
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: false,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        function hasProperty(name) {
            if (registryBuiltins.has(name))
                return true;
            return findProtocol(name) !== null;
        }

        function findProtocol(name) {
            let handle = cachedProtocols[name];
            if (handle === undefined) {
                handle = api.objc_getProtocol(Memory.allocUtf8String(name));
                if (handle.isNull())
                    return null;
                cachedProtocols[name] = handle;
                numCachedProtocols++;
            }

            return new ObjCProtocol(handle);
        }

        function toJSON() {
            return Object.keys(registry).reduce(function (r, name) {
                r[name] = { handle: cachedProtocols[name] };
                return r;
            }, {});
        }

        function toString() {
            return "ProtocolRegistry";
        }

        function valueOf() {
            return "ProtocolRegistry";
        }

        return registry;
    }

    const objCObjectBuiltins = new Set([
        "prototype",
        "constructor",
        "handle",
        "hasOwnProperty",
        "toJSON",
        "toString",
        "valueOf",
        "equals",
        "$kind",
        "$super",
        "$superClass",
        "$class",
        "$className",
        "$moduleName",
        "$protocols",
        "$methods",
        "$ownMethods",
        "$ivars"
    ]);

    function ObjCObject(handle, protocol, cachedIsClass, superSpecifier) {
        let cachedClassHandle = null;
        let cachedKind = null;
        let cachedSuper = null;
        let cachedSuperClass = null;
        let cachedClass = null;
        let cachedClassName = null;
        let cachedModuleName = null;
        let cachedProtocols = null;
        let cachedMethodNames = null;
        let cachedProtocolMethods = null;
        let respondsToSelector = null;
        const cachedMethods = {};
        let cachedNativeMethodNames = null;
        let cachedOwnMethodNames = null;
        let cachedIvars = null;

        handle = getHandle(handle);

        if (cachedIsClass === undefined) {
            // We need to ensure the class is realized, otherwise calling APIs like object_isClass() will crash.
            // The first message delivery will realize the class, but users intercepting calls to objc_msgSend()
            // and inspecting the first argument will run into this situation.
            const klass = api.object_getClass(handle);
            const key = klass.toString();
            if (!realizedClasses.has(key)) {
                api.objc_lookUpClass(api.class_getName(klass));
                realizedClasses.add(key);
            }
        }

        const self = new Proxy(this, {
            has(target, property) {
                return hasProperty(property);
            },
            get(target, property, receiver) {
                switch (property) {
                    case "handle":
                        return handle;
                    case "prototype":
                        return target.prototype;
                    case "constructor":
                        return target.constructor;
                    case "hasOwnProperty":
                        return hasProperty;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                    case "valueOf":
                        const descriptionImpl = receiver.description;
                        if (descriptionImpl !== undefined) {
                            const description = descriptionImpl.call(receiver);
                            if (description !== null)
                                return description.UTF8String.bind(description);
                        }
                        return function () {
                            return receiver.$className;
                        };
                    case "equals":
                        return equals;
                    case "$kind":
                        if (cachedKind === null) {
                            if (isClass())
                                cachedKind = api.class_isMetaClass(handle) ? 'meta-class' : 'class';
                            else
                                cachedKind = 'instance';
                        }
                        return cachedKind;
                    case "$super":
                        if (cachedSuper === null) {
                            const superHandle = api.class_getSuperclass(classHandle());
                            if (!superHandle.isNull()) {
                                const specifier = Memory.alloc(2 * pointerSize);
                                specifier.writePointer(handle);
                                specifier.add(pointerSize).writePointer(superHandle);
                                cachedSuper = [new ObjCObject(handle, undefined, cachedIsClass, specifier)];
                            } else {
                                cachedSuper = [null];
                            }
                        }
                        return cachedSuper[0];
                    case "$superClass":
                        if (cachedSuperClass === null) {
                            const superClassHandle = api.class_getSuperclass(classHandle());
                            if (!superClassHandle.isNull()) {
                                cachedSuperClass = [new ObjCObject(superClassHandle)];
                            } else {
                                cachedSuperClass = [null];
                            }
                        }
                        return cachedSuperClass[0];
                    case "$class":
                        if (cachedClass === null)
                            cachedClass = new ObjCObject(api.object_getClass(handle), undefined, true);
                        return cachedClass;
                    case "$className":
                        if (cachedClassName === null) {
                            if (superSpecifier)
                                cachedClassName = api.class_getName(superSpecifier.add(pointerSize).readPointer()).readUtf8String();
                            else if (isClass())
                                cachedClassName = api.class_getName(handle).readUtf8String();
                            else
                                cachedClassName = api.object_getClassName(handle).readUtf8String();
                        }
                        return cachedClassName;
                    case "$moduleName":
                        if (cachedModuleName === null) {
                            cachedModuleName = api.class_getImageName(classHandle()).readUtf8String();
                        }
                        return cachedModuleName;
                    case "$protocols":
                        if (cachedProtocols === null) {
                            cachedProtocols = {};
                            const numProtocolsBuf = Memory.alloc(pointerSize);
                            const protocolHandles = api.class_copyProtocolList(classHandle(), numProtocolsBuf);
                            if (!protocolHandles.isNull()) {
                                try {
                                    const numProtocols = numProtocolsBuf.readUInt();
                                    for (let i = 0; i !== numProtocols; i++) {
                                        const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                                        const p = new ObjCProtocol(protocolHandle);
                                        cachedProtocols[p.name] = p;
                                    }
                                } finally {
                                    api.free(protocolHandles);
                                }
                            }
                        }
                        return cachedProtocols;
                    case "$methods":
                        if (cachedNativeMethodNames === null) {
                            const klass = superSpecifier ? superSpecifier.add(pointerSize).readPointer() : classHandle();
                            const meta = api.object_getClass(klass);

                            const names = new Set();

                            let cur = meta;
                            do {
                                for (let methodName of collectMethodNames(cur, "+ "))
                                    names.add(methodName);
                                cur = api.class_getSuperclass(cur);
                            } while (!cur.isNull());

                            cur = klass;
                            do {
                                for (let methodName of collectMethodNames(cur, "- "))
                                    names.add(methodName);
                                cur = api.class_getSuperclass(cur);
                            } while (!cur.isNull());

                            cachedNativeMethodNames = Array.from(names);
                        }
                        return cachedNativeMethodNames;
                    case "$ownMethods":
                        if (cachedOwnMethodNames === null) {
                            const klass = superSpecifier ? superSpecifier.add(pointerSize).readPointer() : classHandle();
                            const meta = api.object_getClass(klass);

                            const classMethods = collectMethodNames(meta, "+ ");
                            const instanceMethods = collectMethodNames(klass, "- ");

                            cachedOwnMethodNames = classMethods.concat(instanceMethods);
                        }
                        return cachedOwnMethodNames;
                    case "$ivars":
                        if (cachedIvars === null) {
                            if (isClass())
                                cachedIvars = {};
                            else
                                cachedIvars = new ObjCIvars(self, classHandle());
                        }
                        return cachedIvars;
                    default:
                        if (typeof property === "symbol") {
                            return target[property];
                        }
                        if (protocol) {
                            const details = findProtocolMethod(property);
                            if (details === null || !details.implemented)
                                return undefined;
                        }
                        const wrapper = findMethodWrapper(property);
                        if (wrapper === null)
                            return undefined;
                        return wrapper;
                }
            },
            set(target, property, value, receiver) {
                return false;
            },
            ownKeys(target) {
                if (cachedMethodNames === null) {
                    if (!protocol) {
                        const jsNames = {};
                        const nativeNames = {};

                        let cur = api.object_getClass(handle);
                        do {
                            const numMethodsBuf = Memory.alloc(pointerSize);
                            const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
                            const fullNamePrefix = isClass() ? "+ " : "- ";
                            try {
                                const numMethods = numMethodsBuf.readUInt();
                                for (let i = 0; i !== numMethods; i++) {
                                    const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                                    const sel = api.method_getName(methodHandle);
                                    const nativeName = api.sel_getName(sel).readUtf8String();
                                    if (nativeNames[nativeName] !== undefined)
                                        continue;
                                    nativeNames[nativeName] = nativeName;

                                    const jsName = jsMethodName(nativeName);
                                    let serial = 2;
                                    let name = jsName;
                                    while (jsNames[name] !== undefined) {
                                        serial++;
                                        name = jsName + serial;
                                    }
                                    jsNames[name] = true;

                                    const fullName = fullNamePrefix + nativeName;
                                    if (cachedMethods[fullName] === undefined) {
                                        const details = {
                                            sel: sel,
                                            handle: methodHandle,
                                            wrapper: null
                                        };
                                        cachedMethods[fullName] = details;
                                        cachedMethods[name] = details;
                                    }
                                }
                            } finally {
                                api.free(methodHandles);
                            }
                            cur = api.class_getSuperclass(cur);
                        } while (!cur.isNull());

                        cachedMethodNames = Object.keys(jsNames);
                    } else {
                        const methodNames = [];

                        const protocolMethods = allProtocolMethods();
                        Object.keys(protocolMethods).forEach(function (methodName) {
                            if (methodName[0] !== '+' && methodName[0] !== '-') {
                                const details = protocolMethods[methodName];
                                if (details.implemented) {
                                    methodNames.push(methodName);
                                }
                            }
                        });

                        cachedMethodNames = methodNames;
                    }
                }

                return ['handle'].concat(cachedMethodNames);
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: false,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        if (protocol) {
            respondsToSelector = !isClass() ? findMethodWrapper("- respondsToSelector:") : null;
        }

        return self;

        function hasProperty(name) {
            if (objCObjectBuiltins.has(name))
                return true;
            if (protocol) {
                const details = findProtocolMethod(name);
                return !!(details !== null && details.implemented);
            }
            return findMethod(name) !== null;
        }

        function classHandle() {
            if (cachedClassHandle === null)
                cachedClassHandle = isClass() ? handle : api.object_getClass(handle);
            return cachedClassHandle;
        }

        function isClass() {
            if (cachedIsClass === undefined) {
                if (api.object_isClass)
                    cachedIsClass = !!api.object_isClass(handle);
                else
                    cachedIsClass = !!api.class_isMetaClass(api.object_getClass(handle));
            }
            return cachedIsClass;
        }

        function findMethod(rawName) {
            let method = cachedMethods[rawName];
            if (method !== undefined)
                return method;

            const tokens = parseMethodName(rawName);
            const fullName = tokens[2];

            method = cachedMethods[fullName];
            if (method !== undefined) {
                cachedMethods[rawName] = method;
                return method;
            }

            const kind = tokens[0];
            const name = tokens[1];
            const sel = selector(name);
            const defaultKind = isClass() ? '+' : '-';

            if (protocol) {
                const details = findProtocolMethod(fullName);
                if (details !== null) {
                    method = {
                        sel: sel,
                        types: details.types,
                        wrapper: null,
                        kind
                    };
                }
            }

            if (method === undefined) {
                const methodHandle = (kind === '+') ?
                    api.class_getClassMethod(classHandle(), sel) :
                    api.class_getInstanceMethod(classHandle(), sel);
                if (!methodHandle.isNull()) {
                    method = {
                        sel: sel,
                        handle: methodHandle,
                        wrapper: null,
                        kind
                    };
                } else {
                    if (isClass() || kind !== '-' || name === "forwardingTargetForSelector:" || name === "methodSignatureForSelector:") {
                        return null;
                    }

                    let target = self;
                    if ("- forwardingTargetForSelector:" in self) {
                        const forwardingTarget = self.forwardingTargetForSelector_(sel);
                        if (forwardingTarget !== null && forwardingTarget.$kind === 'instance') {
                            target = forwardingTarget;
                        } else {
                            return null;
                        }
                    } else {
                        return null;
                    }

                    const methodHandle = api.class_getInstanceMethod(api.object_getClass(target.handle), sel);
                    if (methodHandle.isNull()) {
                        return null;
                    }
                    let types = api.method_getTypeEncoding(methodHandle).readUtf8String();
                    if (types === null || types === "") {
                        types = stealTypesFromProtocols(target, fullName);
                        if (types === null)
                            types = stealTypesFromProtocols(self, fullName);
                        if (types === null)
                            return null;
                    }
                    method = {
                        sel,
                        types,
                        wrapper: null,
                        kind
                    };
                }
            }

            cachedMethods[fullName] = method;
            cachedMethods[rawName] = method;
            if (kind === defaultKind)
                cachedMethods[jsMethodName(name)] = method;

            return method;
        }

        function stealTypesFromProtocols(klass, fullName) {
            const candidates = Object.keys(klass.$protocols)
                .map(protocolName => flatProtocolMethods({}, klass.$protocols[protocolName]))
                .reduce((allMethods, methods) => {
                    Object.assign(allMethods, methods);
                    return allMethods;
                }, {});

            const method = candidates[fullName];
            if (method === undefined) {
                return null;
            }
            return method.types;
        }

        function flatProtocolMethods(result, protocol) {
            if (protocol.methods !== undefined) {
                Object.assign(result, protocol.methods);
            }
            if (protocol.protocol !== undefined) {
                flatProtocolMethods(result, protocol.protocol);
            }
            return result;
        }

        function findProtocolMethod(rawName) {
            const protocolMethods = allProtocolMethods();
            const details = protocolMethods[rawName];
            return (details !== undefined) ? details : null;
        }

        function allProtocolMethods() {
            if (cachedProtocolMethods === null) {
                const methods = {};

                const protocols = collectProtocols(protocol);
                const defaultKind = isClass() ? '+' : '-';
                Object.keys(protocols).forEach(function (name) {
                    const p = protocols[name];
                    const m = p.methods;
                    Object.keys(m).forEach(function (fullMethodName) {
                        const method = m[fullMethodName];
                        const methodName = fullMethodName.substr(2);
                        const kind = fullMethodName[0];

                        let didCheckImplemented = false;
                        let implemented = false;
                        const details = {
                            types: method.types
                        };
                        Object.defineProperty(details, 'implemented', {
                            get() {
                                if (!didCheckImplemented) {
                                    if (method.required) {
                                        implemented = true;
                                    } else {
                                        implemented = (respondsToSelector !== null && respondsToSelector.call(self, selector(methodName)));
                                    }
                                    didCheckImplemented = true;
                                }
                                return implemented;
                            }
                        });

                        methods[fullMethodName] = details;
                        if (kind === defaultKind)
                            methods[jsMethodName(methodName)] = details;
                    });
                });

                cachedProtocolMethods = methods;
            }

            return cachedProtocolMethods;
        }

        function findMethodWrapper(name) {
            const method = findMethod(name);
            if (method === null)
                return null;
            let wrapper = method.wrapper;
            if (wrapper === null) {
                wrapper = makeMethodInvocationWrapper(method, self, superSpecifier, defaultInvocationOptions);
                method.wrapper = wrapper;
            }
            return wrapper;
        }

        function parseMethodName(rawName) {
            const match = /([+\-])\s(\S+)/.exec(rawName);
            let name, kind;
            if (match === null) {
                kind = isClass() ? '+' : '-';
                name = objcMethodName(rawName);
            } else {
                kind = match[1];
                name = match[2];
            }
            const fullName = [kind, name].join(' ');
            return [kind, name, fullName];
        }

        function toJSON() {
            return {
                handle: handle.toString()
            };
        }

        function equals(ptr) {
            return handle.equals(getHandle(ptr));
        }
    }

    function getReplacementMethodImplementation(methodHandle) {
        const existingEntry = replacedMethods.get(methodHandle.toString());
        if (existingEntry === undefined)
            return null;
        const [, newImp] = existingEntry;
        return newImp;
    }

    function replaceMethodImplementation(methodHandle, imp) {
        const key = methodHandle.toString();

        let oldImp;
        const existingEntry = replacedMethods.get(key);
        if (existingEntry !== undefined)
            [oldImp] = existingEntry;
        else
            oldImp = api.method_getImplementation(methodHandle);

        if (!imp.equals(oldImp))
            replacedMethods.set(key, [oldImp, imp]);
        else
            replacedMethods.delete(key);

        api.method_setImplementation(methodHandle, imp);
    }

    function collectMethodNames(klass, prefix) {
        const names = [];

        const numMethodsBuf = Memory.alloc(pointerSize);
        const methodHandles = api.class_copyMethodList(klass, numMethodsBuf);
        try {
            const numMethods = numMethodsBuf.readUInt();
            for (let i = 0; i !== numMethods; i++) {
                const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                const sel = api.method_getName(methodHandle);
                const nativeName = api.sel_getName(sel).readUtf8String();
                names.push(prefix + nativeName);
            }
        } finally {
            api.free(methodHandles);
        }

        return names;
    }

    function ObjCProtocol(handle) {
        let cachedName = null;
        let cachedProtocols = null;
        let cachedProperties = null;
        let cachedMethods = null;

        Object.defineProperty(this, 'handle', {
            value: handle,
            enumerable: true
        });

        Object.defineProperty(this, 'name', {
            get() {
                if (cachedName === null)
                    cachedName = api.protocol_getName(handle).readUtf8String();
                return cachedName;
            },
            enumerable: true
        });

        Object.defineProperty(this, 'protocols', {
            get() {
                if (cachedProtocols === null) {
                    cachedProtocols = {};
                    const numProtocolsBuf = Memory.alloc(pointerSize);
                    const protocolHandles = api.protocol_copyProtocolList(handle, numProtocolsBuf);
                    if (!protocolHandles.isNull()) {
                        try {
                            const numProtocols = numProtocolsBuf.readUInt();
                            for (let i = 0; i !== numProtocols; i++) {
                                const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                                const protocol = new ObjCProtocol(protocolHandle);
                                cachedProtocols[protocol.name] = protocol;
                            }
                        } finally {
                            api.free(protocolHandles);
                        }
                    }
                }
                return cachedProtocols;
            },
            enumerable: true
        });

        Object.defineProperty(this, 'properties', {
            get() {
                if (cachedProperties === null) {
                    cachedProperties = {};
                    const numBuf = Memory.alloc(pointerSize);
                    const propertyHandles = api.protocol_copyPropertyList(handle, numBuf);
                    if (!propertyHandles.isNull()) {
                        try {
                            const numProperties = numBuf.readUInt();
                            for (let i = 0; i !== numProperties; i++) {
                                const propertyHandle = propertyHandles.add(i * pointerSize).readPointer();
                                const propName = api.property_getName(propertyHandle).readUtf8String();
                                const attributes = {};
                                const attributeEntries = api.property_copyAttributeList(propertyHandle, numBuf);
                                if (!attributeEntries.isNull()) {
                                    try {
                                        const numAttributeValues = numBuf.readUInt();
                                        for (let j = 0; j !== numAttributeValues; j++) {
                                            const attributeEntry = attributeEntries.add(j * (2 * pointerSize));
                                            const name = attributeEntry.readPointer().readUtf8String();
                                            const value = attributeEntry.add(pointerSize).readPointer().readUtf8String();
                                            attributes[name] = value;
                                        }
                                    } finally {
                                        api.free(attributeEntries);
                                    }
                                }
                                cachedProperties[propName] = attributes;
                            }
                        } finally {
                            api.free(propertyHandles);
                        }
                    }
                }
                return cachedProperties;
            },
            enumerable: true
        });

        Object.defineProperty(this, 'methods', {
            get() {
                if (cachedMethods === null) {
                    cachedMethods = {};
                    const numBuf = Memory.alloc(pointerSize);
                    collectMethods(cachedMethods, numBuf, { required: true, instance: false });
                    collectMethods(cachedMethods, numBuf, { required: false, instance: false });
                    collectMethods(cachedMethods, numBuf, { required: true, instance: true });
                    collectMethods(cachedMethods, numBuf, { required: false, instance: true });
                }
                return cachedMethods;
            },
            enumerable: true
        });

        function collectMethods(methods, numBuf, spec) {
            const methodDescValues = api.protocol_copyMethodDescriptionList(handle, spec.required ? 1 : 0, spec.instance ? 1 : 0, numBuf);
            if (methodDescValues.isNull())
                return;
            try {
                const numMethodDescValues = numBuf.readUInt();
                for (let i = 0; i !== numMethodDescValues; i++) {
                    const methodDesc = methodDescValues.add(i * (2 * pointerSize));
                    const name = (spec.instance ? '- ' : '+ ') + selectorAsString(methodDesc.readPointer());
                    const types = methodDesc.add(pointerSize).readPointer().readUtf8String();
                    methods[name] = {
                        required: spec.required,
                        types: types
                    };
                }
            } finally {
                api.free(methodDescValues);
            }
        }
    }

    const objCIvarsBuiltins = new Set([
        "prototype",
        "constructor",
        "hasOwnProperty",
        "toJSON",
        "toString",
        "valueOf"
    ]);

    function ObjCIvars(instance, classHandle) {
        const ivars = {};
        let cachedIvarNames = null;

        let classHandles = [];

        let currentClassHandle = classHandle;
        do {
            classHandles.unshift(currentClassHandle);
            currentClassHandle = api.class_getSuperclass(currentClassHandle);
        } while (!currentClassHandle.isNull());

        const numIvarsBuf = Memory.alloc(pointerSize);
        classHandles.forEach(c => {
            const ivarHandles = api.class_copyIvarList(c, numIvarsBuf);
            try {
                const numIvars = numIvarsBuf.readUInt();
                for (let i = 0; i !== numIvars; i++) {
                    const handle = ivarHandles.add(i * pointerSize).readPointer();
                    const name = api.ivar_getName(handle).readUtf8String();
                    ivars[name] = [handle, null];
                }
            } finally {
                api.free(ivarHandles);
            }
        });

        const self = new Proxy(this, {
            has(target, property) {
                return hasProperty(property);
            },
            get(target, property, receiver) {
                switch (property) {
                    case "prototype":
                        return target.prototype;
                    case "constructor":
                        return target.constructor;
                    case "hasOwnProperty":
                        return hasProperty;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                        return toString;
                    case "valueOf":
                        return valueOf;
                    default:
                        const ivar = findIvar(property);
                        if (ivar === null)
                            return undefined;
                        return ivar.get();
                }
            },
            set(target, property, value, receiver) {
                const ivar = findIvar(property);
                if (ivar === null)
                    throw new Error("Unknown ivar");
                ivar.set(value);
                return true;
            },
            ownKeys(target) {
                if (cachedIvarNames === null)
                    cachedIvarNames = Object.keys(ivars);
                return cachedIvarNames;
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: true,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        return self;

        function findIvar(name) {
            const entry = ivars[name];
            if (entry === undefined)
                return null;
            let impl = entry[1];
            if (impl === null) {
                const ivar = entry[0];

                const offset = api.ivar_getOffset(ivar).toInt32();
                const address = instance.handle.add(offset);

                const type = parseType(api.ivar_getTypeEncoding(ivar).readUtf8String());
                const fromNative = type.fromNative || identityTransform;
                const toNative = type.toNative || identityTransform;

                let read, write;
                if (name === 'isa') {
                    read = readObjectIsa;
                    write = function () {
                        throw new Error('Unable to set the isa instance variable');
                    };
                } else {
                    read = type.read;
                    write = type.write;
                }

                impl = {
                    get() {
                        return fromNative.call(instance, read(address));
                    },
                    set(value) {
                        write(address, toNative.call(instance, value));
                    }
                };
                entry[1] = impl;
            }
            return impl;
        }

        function hasProperty(name) {
            if (objCIvarsBuiltins.has(name))
                return true;
            return ivars.hasOwnProperty(name);
        }

        function toJSON() {
            return Object.keys(self).reduce(function (result, name) {
                result[name] = self[name];
                return result;
            }, {});
        }

        function toString() {
            return "ObjCIvars";
        }

        function valueOf() {
            return "ObjCIvars";
        }
    }

    let blockDescriptorAllocSize, blockDescriptorDeclaredSize, blockDescriptorOffsets;
    let blockSize, blockOffsets;
    if (pointerSize === 4) {
        blockDescriptorAllocSize = 16; /* sizeof (BlockDescriptor) == 12 */
        blockDescriptorDeclaredSize = 20;
        blockDescriptorOffsets = {
            reserved: 0,
            size: 4,
            rest: 8
        };

        blockSize = 20;
        blockOffsets = {
            isa: 0,
            flags: 4,
            reserved: 8,
            invoke: 12,
            descriptor: 16
        };
    } else {
        blockDescriptorAllocSize = 32; /* sizeof (BlockDescriptor) == 24 */
        blockDescriptorDeclaredSize = 32;
        blockDescriptorOffsets = {
            reserved: 0,
            size: 8,
            rest: 16
        };

        blockSize = 32;
        blockOffsets = {
            isa: 0,
            flags: 8,
            reserved: 12,
            invoke: 16,
            descriptor: 24
        };
    }

    const BLOCK_HAS_COPY_DISPOSE = (1 << 25);
    const BLOCK_HAS_CTOR =         (1 << 26);
    const BLOCK_IS_GLOBAL =        (1 << 28);
    const BLOCK_HAS_STRET =        (1 << 29);
    const BLOCK_HAS_SIGNATURE =    (1 << 30);

    function Block(target, options = defaultInvocationOptions) {
        this._options = options;

        if (target instanceof NativePointer) {
            const descriptor = target.add(blockOffsets.descriptor).readPointer();

            this.handle = target;

            const flags = target.add(blockOffsets.flags).readU32();
            if ((flags & BLOCK_HAS_SIGNATURE) !== 0) {
                const signatureOffset = ((flags & BLOCK_HAS_COPY_DISPOSE) !== 0) ? 2 : 0;
                this.types = descriptor.add(blockDescriptorOffsets.rest + (signatureOffset * pointerSize)).readPointer().readCString();
                this._signature = parseSignature(this.types);
            } else {
                this._signature = null;
            }
        } else {
            this.declare(target);

            const descriptor = Memory.alloc(blockDescriptorAllocSize + blockSize);
            const block = descriptor.add(blockDescriptorAllocSize);
            const typesStr = Memory.allocUtf8String(this.types);

            descriptor.add(blockDescriptorOffsets.reserved).writeULong(0);
            descriptor.add(blockDescriptorOffsets.size).writeULong(blockDescriptorDeclaredSize);
            descriptor.add(blockDescriptorOffsets.rest).writePointer(typesStr);

            block.add(blockOffsets.isa).writePointer(classRegistry.__NSGlobalBlock__);
            block.add(blockOffsets.flags).writeU32(BLOCK_HAS_SIGNATURE | BLOCK_IS_GLOBAL);
            block.add(blockOffsets.reserved).writeU32(0);
            block.add(blockOffsets.descriptor).writePointer(descriptor);

            this.handle = block;

            this._storage = [descriptor, typesStr];

            this.implementation = target.implementation;
        }
    }

    Object.defineProperties(Block.prototype, {
      implementation: {
        enumerable: true,
        get() {
            const address = this.handle.add(blockOffsets.invoke).readPointer().strip();
            const signature = this._getSignature();
            return makeBlockInvocationWrapper(this, signature, new NativeFunction(
                address.sign(),
                signature.retType.type,
                signature.argTypes.map(function (arg) { return arg.type; }),
                this._options));
        },
        set(func) {
            const signature = this._getSignature();
            const callback = new NativeCallback(
                makeBlockImplementationWrapper(this, signature, func),
                signature.retType.type,
                signature.argTypes.map(function (arg) { return arg.type; }));
            this._callback = callback;
            const location = this.handle.add(blockOffsets.invoke);
            const prot = Memory.queryProtection(location);
            const writable = prot.includes('w');
            if (!writable)
                Memory.protect(location, Process.pointerSize, 'rw-');
            location.writePointer(callback.strip().sign('ia', location));
            if (!writable)
                Memory.protect(location, Process.pointerSize, prot);
        }
      },
      declare: {
        value(signature) {
            let types = signature.types;
            if (types === undefined) {
                types = unparseSignature(signature.retType, ['block'].concat(signature.argTypes));
            }
            this.types = types;
            this._signature = parseSignature(types);
        }
      },
      _getSignature: {
        value() {
            const signature = this._signature;
            if (signature === null)
                throw new Error('block is missing signature; call declare()');
            return signature;
        }
      }
    });

    function collectProtocols(p, acc) {
        acc = acc || {};

        acc[p.name] = p;

        const parentProtocols = p.protocols;
        Object.keys(parentProtocols).forEach(function (name) {
            collectProtocols(parentProtocols[name], acc);
        });

        return acc;
    }

    function registerProxy(properties) {
        const protocols = properties.protocols || [];
        const methods = properties.methods || {};
        const events = properties.events || {};
        const supportedSelectors = new Set(
            Object.keys(methods)
                .filter(m => /([+\-])\s(\S+)/.exec(m) !== null)
                .map(m => m.split(' ')[1])
        );

        const proxyMethods = {
            '- dealloc': function () {
                const target = this.data.target;
                if ('- release' in target)
                    target.release();
                unbind(this.self);
                this.super.dealloc();

                const callback = this.data.events.dealloc;
                if (callback !== undefined)
                    callback.call(this);
            },
            '- respondsToSelector:': function (sel) {
                const selector = selectorAsString(sel);
                if (supportedSelectors.has(selector))
                    return true;

                return this.data.target.respondsToSelector_(sel);
            },
            '- forwardingTargetForSelector:': function (sel) {
                const callback = this.data.events.forward;
                if (callback !== undefined)
                    callback.call(this, selectorAsString(sel));
                return this.data.target;
            },
            '- methodSignatureForSelector:': function (sel) {
                return this.data.target.methodSignatureForSelector_(sel);
            },
            '- forwardInvocation:': function (invocation) {
                invocation.invokeWithTarget_(this.data.target);
            }
        };
        for (var key in methods) {
            if (methods.hasOwnProperty(key)) {
                if (proxyMethods.hasOwnProperty(key))
                    throw new Error("The '" + key + "' method is reserved");
                proxyMethods[key] = methods[key];
            }
        }

        const ProxyClass = registerClass({
            name: properties.name,
            super: classRegistry.NSProxy,
            protocols: protocols,
            methods: proxyMethods
        });

        return function (target, data) {
            target = (target instanceof NativePointer) ? new ObjCObject(target) : target;
            data = data || {};

            const instance = ProxyClass.alloc().autorelease();

            const boundData = getBoundData(instance);
            boundData.target = ('- retain' in target) ? target.retain() : target;
            boundData.events = events;
            for (var key in data) {
                if (data.hasOwnProperty(key)) {
                    if (boundData.hasOwnProperty(key))
                        throw new Error("The '" + key + "' property is reserved");
                    boundData[key] = data[key];
                }
            }

            this.handle = instance.handle;
        };
    }

    function registerClass(properties) {
        let name = properties.name;
        if (name === undefined)
            name = makeClassName();
        const superClass = (properties.super !== undefined) ? properties.super : classRegistry.NSObject;
        const protocols = properties.protocols || [];
        const methods = properties.methods || {};
        const methodCallbacks = [];

        const classHandle = api.objc_allocateClassPair(superClass !== null ? superClass.handle : NULL, Memory.allocUtf8String(name), ptr("0"));
        if (classHandle.isNull())
            throw new Error("Unable to register already registered class '" + name + "'");
        const metaClassHandle = api.object_getClass(classHandle);
        try {
            protocols.forEach(function (protocol) {
                api.class_addProtocol(classHandle, protocol.handle);
            });

            Object.keys(methods).forEach(function (rawMethodName) {
                const match = /([+\-])\s(\S+)/.exec(rawMethodName);
                if (match === null)
                    throw new Error("Invalid method name");
                const kind = match[1];
                const name = match[2];

                let method;
                const value = methods[rawMethodName];
                if (typeof value === 'function') {
                    let types = null;
                    if (rawMethodName in superClass) {
                        types = superClass[rawMethodName].types;
                    } else {
                        for (let protocol of protocols) {
                            const method = protocol.methods[rawMethodName];
                            if (method !== undefined) {
                                types = method.types;
                                break;
                            }
                        }
                    }
                    if (types === null)
                        throw new Error("Unable to find '" + rawMethodName + "' in super-class or any of its protocols");
                    method = {
                        types: types,
                        implementation: value
                    };
                } else {
                    method = value;
                }

                const target = (kind === '+') ? metaClassHandle : classHandle;
                let types = method.types;
                if (types === undefined) {
                    types = unparseSignature(method.retType, [(kind === '+') ? 'class' : 'object', 'selector'].concat(method.argTypes));
                }
                const signature = parseSignature(types);
                const implementation = new NativeCallback(
                    makeMethodImplementationWrapper(signature, method.implementation),
                    signature.retType.type,
                    signature.argTypes.map(function (arg) { return arg.type; }));
                methodCallbacks.push(implementation);
                api.class_addMethod(target, selector(name), implementation, Memory.allocUtf8String(types));
            });
        } catch (e) {
            api.objc_disposeClassPair(classHandle);
            throw e;
        }
        api.objc_registerClassPair(classHandle);

        // Keep a reference to the callbacks so they don't get GCed
        classHandle._methodCallbacks = methodCallbacks;

        Script.bindWeak(classHandle, makeClassDestructor(ptr(classHandle)));

        return new ObjCObject(classHandle);
    }

    function makeClassDestructor(classHandle) {
        return function () {
            api.objc_disposeClassPair(classHandle);
        };
    }

    function registerProtocol(properties) {
        let name = properties.name;
        if (name === undefined)
            name = makeProtocolName();
        const protocols = properties.protocols || [];
        const methods = properties.methods || {};

        protocols.forEach(function (protocol) {
            if (!(protocol instanceof ObjCProtocol))
                throw new Error("Expected protocol");
        });

        const methodSpecs = Object.keys(methods).map(function (rawMethodName) {
            const method = methods[rawMethodName];

            const match = /([+\-])\s(\S+)/.exec(rawMethodName);
            if (match === null)
                throw new Error("Invalid method name");
            const kind = match[1];
            const name = match[2];

            let types = method.types;
            if (types === undefined) {
                types = unparseSignature(method.retType, [(kind === '+') ? 'class' : 'object', 'selector'].concat(method.argTypes));
            }

            return {
                kind: kind,
                name: name,
                types: types,
                optional: method.optional
            };
        });

        const handle = api.objc_allocateProtocol(Memory.allocUtf8String(name));
        if (handle.isNull())
            throw new Error("Unable to register already registered protocol '" + name + "'");

        protocols.forEach(function (protocol) {
            api.protocol_addProtocol(handle, protocol.handle);
        });

        methodSpecs.forEach(function (spec) {
            const isRequiredMethod = spec.optional ? 0 : 1;
            const isInstanceMethod = (spec.kind === '-') ? 1 : 0;
            api.protocol_addMethodDescription(handle, selector(spec.name), Memory.allocUtf8String(spec.types), isRequiredMethod, isInstanceMethod);
        });

        api.objc_registerProtocol(handle);

        return new ObjCProtocol(handle);
    }

    function getHandle(obj) {
        if (obj instanceof NativePointer)
            return obj;
        else if (typeof obj === 'object' && obj.hasOwnProperty('handle'))
            return obj.handle;
        else
            throw new Error("Expected NativePointer or ObjC.Object instance");
    }

    function bind(obj, data) {
        const handle = getHandle(obj);
        const self = (obj instanceof ObjCObject) ? obj : new ObjCObject(handle);
        bindings.set(handle.toString(), {
            self: self,
            super: self.$super,
            data: data
        });
    }

    function unbind(obj) {
        const handle = getHandle(obj);
        bindings.delete(handle.toString());
    }

    function getBoundData(obj) {
        return getBinding(obj).data;
    }

    function getBinding(obj) {
        const handle = getHandle(obj);
        const key = handle.toString();
        let binding = bindings.get(key);
        if (binding === undefined) {
            const self = (obj instanceof ObjCObject) ? obj : new ObjCObject(handle);
            binding = {
                self: self,
                super: self.$super,
                data: {}
            };
            bindings.set(key, binding);
        }
        return binding;
    }

    function enumerateLoadedClasses(...args) {
        const allModules = new ModuleMap();
        let unfiltered = false;

        let callbacks;
        let modules;
        if (args.length === 1) {
            callbacks = args[0];
        } else {
            callbacks = args[1];

            const options = args[0];
            modules = options.ownedBy;
        }
        if (modules === undefined) {
            modules = allModules;
            unfiltered = true;
        }

        const classGetName = api.class_getName;
        const onMatch = callbacks.onMatch.bind(callbacks);
        const swiftNominalTypeDescriptorOffset = ((pointerSize === 8) ? 8 : 11) * pointerSize;

        const numClasses = api.objc_getClassList(NULL, 0);
        const classHandles = Memory.alloc(numClasses * pointerSize);
        api.objc_getClassList(classHandles, numClasses);

        for (let i = 0; i !== numClasses; i++) {
            const classHandle = classHandles.add(i * pointerSize).readPointer();

            const rawName = classGetName(classHandle);
            let name = null;

            let modulePath = modules.findPath(rawName);
            const possiblySwift = (modulePath === null) && (unfiltered || allModules.findPath(rawName) === null);
            if (possiblySwift) {
                name = rawName.readCString();
                const probablySwift = name.indexOf('.') !== -1;
                if (probablySwift) {
                    const nominalTypeDescriptor = classHandle.add(swiftNominalTypeDescriptorOffset).readPointer();
                    modulePath = modules.findPath(nominalTypeDescriptor);
                }
            }

            if (modulePath !== null) {
                if (name === null)
                    name = rawName.readUtf8String();
                onMatch(name, modulePath);
            }
        }

        callbacks.onComplete();
    }

    function enumerateLoadedClassesSync(options = {}) {
        const result = {};
        enumerateLoadedClasses(options, {
            onMatch(name, owner) {
                let group = result[owner];
                if (group === undefined) {
                    group = [];
                    result[owner] = group;
                }
                group.push(name);
            },
            onComplete() {
            }
        });
        return result;
    }

    function choose(specifier, callbacks) {
        let cls = specifier;
        let subclasses = true;
        if (!(specifier instanceof ObjCObject) && typeof specifier === 'object') {
            cls = specifier.class;
            if (specifier.hasOwnProperty('subclasses'))
                subclasses = specifier.subclasses;
        }
        if (!(cls instanceof ObjCObject && (cls.$kind === 'class' || cls.$kind === 'meta-class')))
            throw new Error("Expected an ObjC.Object for a class or meta-class");

        const matches = fastpaths.get()
            .choose(cls, subclasses)
            .map(handle => new ObjCObject(handle));
        for (const match of matches) {
            const result = callbacks.onMatch(match);
            if (result === 'stop')
                break;
        }

        callbacks.onComplete();
    }

    function makeMethodInvocationWrapper(method, owner, superSpecifier, invocationOptions) {
        const sel = method.sel;
        let handle = method.handle;
        let types;
        if (handle === undefined) {
            handle = null;
            types = method.types;
        } else {
            types = api.method_getTypeEncoding(handle).readUtf8String();
        }

        const signature = parseSignature(types);
        const retType = signature.retType;
        const argTypes = signature.argTypes.slice(2);

        const objc_msgSend = superSpecifier
            ? getMsgSendSuperImpl(signature, invocationOptions)
            : getMsgSendImpl(signature, invocationOptions);

        const argVariableNames = argTypes.map(function (t, i) {
            return "a" + (i + 1);
        });
        const callArgs = [
            superSpecifier ? "superSpecifier" : "this",
            "sel"
        ].concat(argTypes.map(function (t, i) {
            if (t.toNative) {
                return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
            }
            return argVariableNames[i];
        }));
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.fromNative) {
            returnCaptureLeft = "return retType.fromNative.call(this, ";
            returnCaptureRight = ")";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }

        const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " +
            returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; m;");

        Object.defineProperty(m, 'handle', {
            enumerable: true,
            get: getMethodHandle
        });

        m.selector = sel;

        Object.defineProperty(m, 'implementation', {
            enumerable: true,
            get() {
                const h = getMethodHandle();

                const impl = new NativeFunction(api.method_getImplementation(h), m.returnType, m.argumentTypes, invocationOptions);

                const newImp = getReplacementMethodImplementation(h);
                if (newImp !== null)
                    impl._callback = newImp;

                return impl;
            },
            set(imp) {
                replaceMethodImplementation(getMethodHandle(), imp);
            }
        });

        m.returnType = retType.type;

        m.argumentTypes = signature.argTypes.map(t => t.type);

        m.types = types;

        Object.defineProperty(m, 'symbol', {
            enumerable: true,
            get() {
                return `${method.kind}[${owner.$className} ${selectorAsString(sel)}]`;
            }
        });

        m.clone = function (options) {
            return makeMethodInvocationWrapper(method, owner, superSpecifier, options);
        };

        function getMethodHandle() {
            if (handle === null) {
                if (owner.$kind === 'instance') {
                    let cur = owner;
                    do {
                        if ("- forwardingTargetForSelector:" in cur) {
                            const target = cur.forwardingTargetForSelector_(sel);
                            if (target === null)
                                break;
                            if (target.$kind !== 'instance')
                                break;
                            const h = api.class_getInstanceMethod(target.$class.handle, sel);
                            if (!h.isNull())
                                handle = h;
                            else
                                cur = target;
                        } else {
                            break;
                        }
                    } while (handle === null);
                }

                if (handle === null)
                    throw new Error("Unable to find method handle of proxied function");
            }

            return handle;
        }

        return m;
    }

    function makeMethodImplementationWrapper(signature, implementation) {
        const retType = signature.retType;
        const argTypes = signature.argTypes;

        const argVariableNames = argTypes.map(function (t, i) {
            if (i === 0)
                return "handle";
            else if (i === 1)
                return "sel";
            else
                return "a" + (i - 1);
        });
        const callArgs = argTypes.slice(2).map(function (t, i) {
            const argVariableName = argVariableNames[2 + i];
            if (t.fromNative) {
                return "argTypes[" + (2 + i) + "].fromNative.call(self, " + argVariableName + ")";
            }
            return argVariableName;
        });
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.toNative) {
            returnCaptureLeft = "return retType.toNative.call(self, ";
            returnCaptureRight = ")";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }

        const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " +
            "var binding = getBinding(handle);" +
            "var self = binding.self;" +
            returnCaptureLeft + "implementation.call(binding" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; m;");

        return m;
    }

    function makeBlockInvocationWrapper(block, signature, implementation) {
        const retType = signature.retType;
        const argTypes = signature.argTypes.slice(1);

        const argVariableNames = argTypes.map(function (t, i) {
            return "a" + (i + 1);
        });
        const callArgs = argTypes.map(function (t, i) {
            if (t.toNative) {
                return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
            }
            return argVariableNames[i];
        });
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.fromNative) {
            returnCaptureLeft = "return retType.fromNative.call(this, ";
            returnCaptureRight = ")";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }
        const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " +
            returnCaptureLeft + "implementation(this" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; f;");

        return f.bind(block);
    }

    function makeBlockImplementationWrapper(block, signature, implementation) {
        const retType = signature.retType;
        const argTypes = signature.argTypes;

        const argVariableNames = argTypes.map(function (t, i) {
            if (i === 0)
                return "handle";
            else
                return "a" + i;
        });
        const callArgs = argTypes.slice(1).map(function (t, i) {
            const argVariableName = argVariableNames[1 + i];
            if (t.fromNative) {
                return "argTypes[" + (1 + i) + "].fromNative.call(this, " + argVariableName + ")";
            }
            return argVariableName;
        });
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.toNative) {
            returnCaptureLeft = "return retType.toNative.call(this, ";
            returnCaptureRight = ")";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }

        const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " +
            "if (!this.handle.equals(handle))" +
                "this.handle = handle;" +
            returnCaptureLeft + "implementation.call(block" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; f;");

        return f.bind(block);
    }

    function rawFridaType(t) {
        return (t === 'object') ? 'pointer' : t;
    }

    function makeClassName() {
        for (let i = 1; true; i++) {
            const name = "FridaAnonymousClass" + i;
            if (!(name in classRegistry)) {
                return name;
            }
        }
    }

    function makeProtocolName() {
        for (let i = 1; true; i++) {
            const name = "FridaAnonymousProtocol" + i;
            if (!(name in protocolRegistry)) {
                return name;
            }
        }
    }

    function objcMethodName(name) {
        return name.replace(/_/g, ":");
    }

    function jsMethodName(name) {
        let result = name.replace(/:/g, "_");
        if (objCObjectBuiltins.has(result))
            result += "2";
        return result;
    }

    const isaMasks = {
        x64: '0x7ffffffffff8',
        arm64: '0xffffffff8'
    };

    const rawMask = isaMasks[Process.arch];
    if (rawMask !== undefined) {
        const mask = ptr(rawMask);
        readObjectIsa = function (p) {
            return p.readPointer().and(mask);
        };
    } else {
        readObjectIsa = function (p) {
            return p.readPointer();
        };
    }

    function getMsgSendImpl(signature, invocationOptions) {
        return resolveMsgSendImpl(msgSendBySignatureId, signature, invocationOptions, false);
    }

    function getMsgSendSuperImpl(signature, invocationOptions) {
        return resolveMsgSendImpl(msgSendSuperBySignatureId, signature, invocationOptions, true);
    }

    function resolveMsgSendImpl(cache, signature, invocationOptions, isSuper) {
        if (invocationOptions !== defaultInvocationOptions)
            return makeMsgSendImpl(signature, invocationOptions, isSuper);

        const {id} = signature;

        let impl = cache.get(id);
        if (impl === undefined) {
            impl = makeMsgSendImpl(signature, invocationOptions, isSuper);
            cache.set(id, impl);
        }

        return impl;
    }

    function makeMsgSendImpl(signature, invocationOptions, isSuper) {
        const retType = signature.retType.type;
        const argTypes = signature.argTypes.map(function (t) { return t.type; });

        const components = ['objc_msgSend'];

        if (isSuper)
            components.push('Super');

        const returnsStruct = retType instanceof Array;
        if (returnsStruct && !typeFitsInRegisters(retType))
            components.push('_stret');
        else if (retType === 'float' || retType === 'double')
            components.push('_fpret');

        const name = components.join('');

        return new NativeFunction(api[name], retType, argTypes, invocationOptions);
    }

    function typeFitsInRegisters(type) {
        if (Process.arch !== 'x64')
            return false;

        const size = sizeOfTypeOnX64(type);

        // It's actually way more complex than this, plus, we ignore alignment.
        // But at least we can assume that no SSE types are involved, as we don't yet support them...
        return size <= 16;
    }

    function sizeOfTypeOnX64(type) {
        if (type instanceof Array)
            return type.reduce((total, field) => total + sizeOfTypeOnX64(field), 0);

        switch (type) {
            case 'bool':
            case 'char':
            case 'uchar':
                return 1;
            case 'int16':
            case 'uint16':
                return 2;
            case 'int':
            case 'int32':
            case 'uint':
            case 'uint32':
            case 'float':
                return 4;
            default:
                return 8;
        }
    }

    function unparseSignature(retType, argTypes) {
        const retTypeId = typeIdFromAlias(retType);
        const argTypeIds = argTypes.map(typeIdFromAlias);

        const argSizes = argTypeIds.map(id => singularTypeById[id].size);
        const frameSize = argSizes.reduce((total, size) => total + size, 0);

        let frameOffset = 0;
        return retTypeId + frameSize + argTypeIds.map((id, i) => {
            const result = id + frameOffset;
            frameOffset += argSizes[i];
            return result;
        }).join("");
    }

    function parseSignature(sig) {
        const cursor = [sig, 0];

        parseQualifiers(cursor);
        const retType = readType(cursor);
        readNumber(cursor);

        const argTypes = [];

        let id = JSON.stringify(retType.type);

        while (dataAvailable(cursor)) {
            parseQualifiers(cursor);
            const argType = readType(cursor);
            readNumber(cursor);
            argTypes.push(argType);

            id += JSON.stringify(argType.type);
        }

        return {
            id: id,
            retType: retType,
            argTypes: argTypes
        };
    }

    function parseType(type) {
        const cursor = [type, 0];

        return readType(cursor);
    }

    function readType(cursor) {
        let id = readChar(cursor);
        if (id === '@') {
            let next = peekChar(cursor);
            if (next === '?') {
                id += next;
                skipChar(cursor);
                if (peekChar(cursor) === '<')
                    skipExtendedBlock(cursor);
            } else if (next === '"') {
                skipChar(cursor);
                readUntil('"', cursor);
            }
        } else if (id === '^') {
            let next = peekChar(cursor);
            if (next === '@') {
                id += next;
                skipChar(cursor);
            }
        }

        const type = singularTypeById[id];
        if (type !== undefined) {
            return type;
        } else if (id === '[') {
            const length = readNumber(cursor);
            const elementType = readType(cursor);
            skipChar(cursor); // ']'
            return arrayType(length, elementType);
        } else if (id === '{') {
            if (!tokenExistsAhead('=', '}', cursor)) {
                readUntil('}', cursor);
                return structType([]);
            }
            readUntil('=', cursor);
            const structFields = [];
            let ch;
            while ((ch = peekChar(cursor)) !== '}') {
                if (ch === '"') {
                    skipChar(cursor);
                    readUntil('"', cursor);
                }
                structFields.push(readType(cursor));
            }
            skipChar(cursor); // '}'
            return structType(structFields);
        } else if (id === '(') {
            readUntil('=', cursor);
            const unionFields = [];
            while (peekChar(cursor) !== ')')
                unionFields.push(readType(cursor));
            skipChar(cursor); // ')'
            return unionType(unionFields);
        } else if (id === 'b') {
            readNumber(cursor);
            return singularTypeById.i;
        } else if (id === '^') {
            readType(cursor);
            return singularTypeById['?'];
        } else if (modifiers.has(id)) {
            return readType(cursor);
        } else {
            throw new Error("Unable to handle type " + id);
        }
    }

    function skipExtendedBlock(cursor) {
        let ch;
        skipChar(cursor); // '<'
        while ((ch = peekChar(cursor)) !== '>') {
            if (peekChar(cursor) === '<') {
                skipExtendedBlock(cursor);
            } else {
                skipChar(cursor);
                if (ch === '"')
                    readUntil('"', cursor);
            }
        }
        skipChar(cursor); // '>'
    }

    function readNumber(cursor) {
        let result = "";
        while (dataAvailable(cursor)) {
            const c = peekChar(cursor);
            const v = c.charCodeAt(0);
            const isDigit = v >= 0x30 && v <= 0x39;
            if (isDigit) {
                result += c;
                skipChar(cursor);
            } else {
                break;
            }
        }
        return parseInt(result);
    }

    function readUntil(token, cursor) {
        const buffer = cursor[0];
        const offset = cursor[1];
        const index = buffer.indexOf(token, offset);
        if (index === -1)
            throw new Error("Expected token '" + token + "' not found");
        const result = buffer.substring(offset, index);
        cursor[1] = index + 1;
        return result;
    }

    function readChar(cursor) {
        return cursor[0][cursor[1]++];
    }

    function peekChar(cursor) {
        return cursor[0][cursor[1]];
    }

    function tokenExistsAhead(token, terminator, cursor) {
        const [buffer, offset] = cursor;

        const tokenIndex = buffer.indexOf(token, offset);
        if (tokenIndex === -1)
            return false;

        const terminatorIndex = buffer.indexOf(terminator, offset);
        if (terminatorIndex === -1)
            throw new Error("Expected to find terminator: " + terminator);

        return tokenIndex < terminatorIndex;
    }

    function skipChar(cursor) {
        cursor[1]++;
    }

    function dataAvailable(cursor) {
        return cursor[1] !== cursor[0].length;
    }

    const qualifierById = {
        'r': 'const',
        'n': 'in',
        'N': 'inout',
        'o': 'out',
        'O': 'bycopy',
        'R': 'byref',
        'V': 'oneway'
    };

    function parseQualifiers(cursor) {
        const qualifiers = [];
        while (true) {
            const q = qualifierById[peekChar(cursor)];
            if (q === undefined)
                break;
            qualifiers.push(q);
            skipChar(cursor);
        }
        return qualifiers;
    }

    const idByAlias = {
        'char': 'c',
        'int': 'i',
        'int16': 's',
        'int32': 'i',
        'int64': 'q',
        'uchar': 'C',
        'uint': 'I',
        'uint16': 'S',
        'uint32': 'I',
        'uint64': 'Q',
        'float': 'f',
        'double': 'd',
        'bool': 'B',
        'void': 'v',
        'string': '*',
        'object': '@',
        'block': '@?',
        'class': '#',
        'selector': ':',
        'pointer': '^v'
    };

    function typeIdFromAlias(alias) {
        if (typeof alias === 'object' && alias !== null)
            return `@"${alias.type}"`;

        const id = idByAlias[alias];
        if (id === undefined)
            throw new Error("No known encoding for type " + alias);
        return id;
    }

    const fromNativeId = function (h) {
        if (h.isNull()) {
            return null;
        } else if (h.toString(16) === this.handle.toString(16)) {
            return this;
        } else {
            return new ObjCObject(h);
        }
    };

    const toNativeId = function (v) {
        if (v === null)
            return NULL;

        const type = typeof v;
        if (type === 'string') {
            if (cachedNSStringCtor === null) {
                cachedNSString = classRegistry.NSString;
                cachedNSStringCtor = cachedNSString.stringWithUTF8String_;
            }
            return cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(v));
        } else if (type === 'number') {
            if (cachedNSNumberCtor === null) {
                cachedNSNumber = classRegistry.NSNumber;
                cachedNSNumberCtor = cachedNSNumber.numberWithDouble_;
            }
            return cachedNSNumberCtor.call(cachedNSNumber, v);
        }

        return v;
    };

    const fromNativeBlock = function (h) {
        if (h.isNull()) {
            return null;
        } else if (h.toString(16) === this.handle.toString(16)) {
            return this;
        } else {
            return new Block(h);
        }
    };

    const toNativeBlock = function (v) {
        return (v !== null) ? v : NULL;
    };

    const toNativeObjectArray = function (v) {
        if (v instanceof Array) {
            const length = v.length;
            const array = Memory.alloc(length * pointerSize);
            for (let i = 0; i !== length; i++)
                array.add(i * pointerSize).writePointer(toNativeId(v[i]));
            return array;
        }

        return v;
    };

    function arrayType(length, elementType) {
        return {
            type: 'pointer',
            read(address) {
                const result = [];

                const elementSize = elementType.size;
                for (let index = 0; index !== length; index++) {
                    result.push(elementType.read(address.add(index * elementSize)));
                }

                return result;
            },
            write(address, values) {
                const elementSize = elementType.size;
                values.forEach((value, index) => {
                    elementType.write(address.add(index * elementSize), value);
                });
            }
        };
    }

    function structType(fieldTypes) {
        let fromNative, toNative;

        if (fieldTypes.some(function (t) { return !!t.fromNative; })) {
            const fromTransforms = fieldTypes.map(function (t) {
                if (t.fromNative)
                    return t.fromNative;
                else
                    return identityTransform;
            });
            fromNative = function (v) {
                return v.map(function (e, i) {
                    return fromTransforms[i].call(this, e);
                });
            };
        } else {
            fromNative = identityTransform;
        }

        if (fieldTypes.some(function (t) { return !!t.toNative; })) {
            const toTransforms = fieldTypes.map(function (t) {
                if (t.toNative)
                    return t.toNative;
                else
                    return identityTransform;
            });
            toNative = function (v) {
                return v.map(function (e, i) {
                    return toTransforms[i].call(this, e);
                });
            };
        } else {
            toNative = identityTransform;
        }

        const [totalSize, fieldOffsets] = fieldTypes.reduce(function (result, t) {
            const [previousOffset, offsets] = result;

            const {size} = t;
            const offset = align(previousOffset, size);
            offsets.push(offset);

            return [offset + size, offsets];
        }, [0, []]);

        return {
            type: fieldTypes.map(t => t.type),
            size: totalSize,
            read(address) {
                return fieldTypes.map((type, index) => type.read(address.add(fieldOffsets[index])));
            },
            write(address, values) {
                values.forEach((value, index) => {
                    fieldTypes[index].write(address.add(fieldOffsets[index]), value);
                });
            },
            fromNative: fromNative,
            toNative: toNative
        };
    }

    function unionType(fieldTypes) {
        const largestType = fieldTypes.reduce(function (largest, t) {
            if (t.size > largest.size)
                return t;
            else
                return largest;
        }, fieldTypes[0]);

        let fromNative, toNative;

        if (largestType.fromNative) {
            const fromTransform = largestType.fromNative;
            fromNative = function (v) {
                return fromTransform.call(this, v[0]);
            };
        } else {
            fromNative = function (v) {
                return v[0];
            };
        }

        if (largestType.toNative) {
            const toTransform = largestType.toNative;
            toNative = function (v) {
                return [toTransform.call(this, v)];
            };
        } else {
            toNative = function (v) {
                return [v];
            };
        }

        return {
            type: [largestType.type],
            size: largestType.size,
            read: largestType.read,
            write: largestType.write,
            fromNative: fromNative,
            toNative: toNative
        };
    }

    const longBits = (pointerSize == 8 && Process.platform !== 'windows') ? 64 : 32;

    modifiers = new Set([
      'j', // complex
      'A', // atomic
      'r', // const
      'n', // in
      'N', // inout
      'o', // out
      'O', // by copy
      'R', // by ref
      'V', // one way
      '+'  // GNU register
    ]);

    singularTypeById = {
        'c': {
            type: 'char',
            size: 1,
            read: address => address.readS8(),
            write: (address, value) => { address.writeS8(value); },
            toNative(v) {
                if (typeof v === 'boolean') {
                    return v ? 1 : 0;
                }
                return v;
            }
        },
        'i': {
            type: 'int',
            size: 4,
            read: address => address.readInt(),
            write: (address, value) => { address.writeInt(value); }
        },
        's': {
            type: 'int16',
            size: 2,
            read: address => address.readS16(),
            write: (address, value) => { address.writeS16(value); }
        },
        'l': {
            type: 'int32',
            size: 4,
            read: address => address.readS32(),
            write: (address, value) => { address.writeS32(value); }
        },
        'q': {
            type: 'int64',
            size: 8,
            read: address => address.readS64(),
            write: (address, value) => { address.writeS64(value); }
        },
        'C': {
            type: 'uchar',
            size: 1,
            read: address => address.readU8(),
            write: (address, value) => { address.writeU8(value); }
        },
        'I': {
            type: 'uint',
            size: 4,
            read: address => address.readUInt(),
            write: (address, value) => { address.writeUInt(value); }
        },
        'S': {
            type: 'uint16',
            size: 2,
            read: address => address.readU16(),
            write: (address, value) => { address.writeU16(value); }
        },
        'L': {
            type: 'uint' + longBits,
            size: longBits / 8,
            read: address => address.readULong(),
            write: (address, value) => { address.writeULong(value); }
        },
        'Q': {
            type: 'uint64',
            size: 8,
            read: address => address.readU64(),
            write: (address, value) => { address.writeU64(value); }
        },
        'f': {
            type: 'float',
            size: 4,
            read: address => address.readFloat(),
            write: (address, value) => { address.writeFloat(value); }
        },
        'd': {
            type: 'double',
            size: 8,
            read: address => address.readDouble(),
            write: (address, value) => { address.writeDouble(value); }
        },
        'B': {
            type: 'bool',
            size: 1,
            read: address => address.readU8(),
            write: (address, value) => { address.writeU8(value); },
            fromNative(v) {
                return v ? true : false;
            },
            toNative(v) {
                return v ? 1 : 0;
            }
        },
        'v': {
            type: 'void',
            size: 0
        },
        '*': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative(h) {
                return h.readUtf8String();
            }
        },
        '@': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative: fromNativeId,
            toNative: toNativeId
        },
        '@?': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative: fromNativeBlock,
            toNative: toNativeBlock
        },
        '^@': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            toNative: toNativeObjectArray
        },
        '^v': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
        },
        '#': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative: fromNativeId,
            toNative: toNativeId
        },
        ':': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); }
        },
        '?': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); }
        }
    };

    function identityTransform(v) {
        return v;
    }

    function align(value, boundary) {
        const remainder = value % boundary;
        return (remainder === 0) ? value : value + (boundary - remainder);
    }
}

const runtime = new Runtime();
export default runtime;
