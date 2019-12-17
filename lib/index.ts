/* jshint esnext: true, evil: true */

import {getApi, defaultInvocationOptions} from "./api";
import {getGonzales} from "./gonzales";

export namespace Runtime {
    interface Cache<T> {
        [name: string]: T;
    }

    interface ObjectConstructor {
        new (handle: NativePointer,
             protocol?: ObjC.Protocol,
             cachedIsClass?: boolean,
             superSpecifier?: NativePointer): ObjC.Object;
    }

    interface ProtocolConstructor {
        new (handle: NativePointer): ObjC.Protocol;
    }

    interface BlockConstructor {
        new (handle: NativePointer): ObjC.Block;
    }

    interface ProtocolMethodInfo {
        types: string;
        implemented: boolean;
    }

    interface ObjectMethodInfo {
        sel: NativePointer;
        types?: string;
        handle?: NativePointer | null;
        wrapper: ObjC.ObjectMethod | null;
    }

    interface MethodSignature {
        id: string;
        retType: TypeDescription;
        argTypes: TypeDescription[];
    }

    interface TypeDescription {
        type: string | string[],
        size: number,
        read: (address: NativePointer) => any,
        write: (address: NativePointer, value: any) => void,
        fromNative?: (this: any, value: NativeReturnValue) => any;
        toNative?: (value: any) => NativeArgumentValue;
    }

    type Nullable<T> = T | null;

    const pointerSize = Process.pointerSize;
    const realizedClasses = new Set<string>([]);
    const classRegistry = <Cache<ObjC.Object>> ClassRegistry();
    const protocolRegistry = <Cache<ObjC.Protocol>> ProtocolRegistry();
    const scheduledWork = <Cache<AnyFunction>> {};
    let nextId = 1;
    let workCallback = <Nullable<NativeCallback>> null;
    let NSAutoreleasePool = <Nullable<ObjC.Object>> null;
    const bindings = <Cache<ObjC.UserMethodInvocation<any, any, any>>> {};
    let readObjectIsa = <Nullable<(p: NativePointer) => NativePointer>> null;
    const msgSendBySignatureId = <Cache<NativeFunction>> {};
    const msgSendSuperBySignatureId = <Cache<NativeFunction>> {};
    let cachedNSString = <Nullable<ObjC.Object>> null;
    let cachedNSStringCtor = <Nullable<ObjC.ObjectMethod>> null;
    let cachedNSNumber = <Nullable<ObjC.Object>> null;
    let cachedNSNumberCtor = <Nullable<ObjC.ObjectMethod>> null;
    let singularTypeById = <Nullable<Cache<TypeDescription>>> null;
    const PRIV = Symbol('priv');

    export const api = <Cache<NativeFunction>> getApi();

    export const available = api !== null;

    export const classes = available ? classRegistry : {};

    export const protocols = available ? protocolRegistry : {};

    export const Object = <ObjectConstructor> (<any> ObjCObject);

    export const Protocol = <ProtocolConstructor> (<any> ObjCProtocol);

    export const Block = <BlockConstructor> (<any> ObjCBlock);

    export const mainQueue = api._dispatch_main_q;

    export function registerProxy(properties: ObjC.ProxySpec) {
        type ProxyMethod = ObjC.UserMethodImplementation<any, any, any>
            | ObjC.MethodSpec<ObjC.UserMethodImplementation<any, any, any>>;

        const protocols = properties.protocols || [];
        const methods = properties.methods || {};
        const events = properties.events || {};

        const proxyMethods = <Cache<ProxyMethod>> {
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
        for (let key in methods) {
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

        return class implements ObjC.ProxyInstance {
            public handle: NativePointer;
            constructor(target: NativePointer | ObjC.Object, data?: ObjC.InstanceData) {
                target = (target instanceof NativePointer) ? new Runtime.Object(target) : target;
                data = data || {};

                const instance = ProxyClass.alloc().autorelease();

                const boundData = getBoundData(instance);
                boundData.target = ('- retain' in target) ? target.retain() : target;
                boundData.events = events;
                for (let key in data) {
                    if (data.hasOwnProperty(key)) {
                        if (boundData.hasOwnProperty(key))
                            throw new Error("The '" + key + "' property is reserved");
                        boundData[key] = data[key];
                    }
                }

                this.handle = instance.handle;
            }
        };
    }

    export function registerClass(properties: ObjC.ClassSpec) {
        let name = properties.name;
        if (name === undefined)
            name = makeClassName();
        const superClass = (properties.super !== undefined) ? properties.super : classRegistry.NSObject;
        const protocols = properties.protocols || [];
        const methods = properties.methods || {};
        const methodCallbacks = <NativeCallback[]> [];

        const classHandle = <NativePointer> api.objc_allocateClassPair(
            superClass !== null ? superClass.handle : NULL,
            Memory.allocUtf8String(name),
            NULL);
        if (classHandle.isNull())
            throw new Error("Unable to register already registered class '" + name + "'");
        const metaClassHandle = api.object_getClass(classHandle);
        try {
            protocols.forEach(function (protocol) {
                api.class_addProtocol(classHandle, protocol.handle);
            });

            global.Object.keys(methods).forEach(function (rawMethodName) {
                const match = /([+\-])\s(\S+)/.exec(rawMethodName);
                if (match === null)
                    throw new Error("Invalid method name");
                const kind = match[1];
                const name = match[2];

                let method;
                const value = methods[rawMethodName];
                if (typeof value === 'function') {
                    let types = null;
                    if (superClass !== null && rawMethodName in superClass) {
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
                let types = (<ObjC.DetailedMethodSpec<any>> method).types;
                if (types === undefined) {
                    const retType = (<ObjC.SimpleMethodSpec<any>> method).retType;
                    const argTypes = (<ObjC.SimpleMethodSpec<any>> method).argTypes;
                    types = unparseSignature(retType, [(kind === '+') ? 'class' : 'object', 'selector'].concat(argTypes));
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
        (<any> classHandle)._methodCallbacks = methodCallbacks;

        WeakRef.bind(classHandle, makeClassDestructor(classHandle));

        return new Runtime.Object(classHandle);

        function makeClassName() {
            for (let i = 1; true; i++) {
                const name = "FridaAnonymousClass" + i;
                if (!(name in classRegistry)) {
                    return name;
                }
            }
        }

        function makeClassDestructor(classHandle: NativePointer) {
            return function () {
                api.objc_disposeClassPair(classHandle);
            };
        }

        function makeMethodImplementationWrapper(signature: MethodSignature,
                                                 implementation: ObjC.UserMethodImplementation<any, any, any>) {
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
    }

    export function registerProtocol(properties: ObjC.ProtocolSpec) {
        let name = properties.name;
        if (name === undefined)
            name = makeProtocolName();
        const protocols = properties.protocols || [];
        const methods = properties.methods || {};

        protocols.forEach(function (protocol) {
            if (!(protocol instanceof ObjCProtocol))
                throw new Error("Expected protocol");
        });

        const methodSpecs = global.Object.keys(methods).map(function (rawMethodName) {
            const method = methods[rawMethodName];

            const match = /([+\-])\s(\S+)/.exec(rawMethodName);
            if (match === null)
                throw new Error("Invalid method name");
            const kind = match[1];
            const name = match[2];

            let types = (<ObjC.DetailedProtocolMethodSpec> method).types;
            if (types === undefined) {
                const retType = (<ObjC.SimpleProtocolMethodSpec> method).retType;
                const argTypes = (<ObjC.SimpleProtocolMethodSpec> method).argTypes;
                types = unparseSignature(retType, [(kind === '+') ? 'class' : 'object', 'selector'].concat(argTypes));
            }

            return {
                kind: kind,
                name: name,
                types: types,
                optional: method.optional
            };
        });

        const handle = <NativePointer> api.objc_allocateProtocol(Memory.allocUtf8String(name));
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

        return new Runtime.Protocol(handle);

        function makeProtocolName() {
            for (let i = 1; true; i++) {
                const name = "FridaAnonymousProtocol" + i;
                if (!(name in protocolRegistry)) {
                    return name;
                }
            }
        }
    }

    export function bind(obj: ObjC.Object | NativePointer, data: WeakRefCallback) {
        const handle = getHandle(obj);
        const self = (obj instanceof Runtime.Object) ? obj : new Runtime.Object(handle);
        bindings[handle.toString()] = {
            self: self,
            super: self.$super,
            data: data
        };
    }

    export function unbind(obj: ObjC.Object | NativePointer) {
        const handle = getHandle(obj);
        delete bindings[handle.toString()];
    }

    export function getBoundData(obj: ObjC.Object | NativePointer) {
        return getBinding(obj).data;

        function getBinding(obj: ObjC.Object | NativePointer) {
            const handle = getHandle(obj);
            const key = handle.toString();
            let binding = bindings[key];
            if (binding === undefined) {
                const self = (obj instanceof Runtime.Object) ? obj : new Runtime.Object(handle);
                binding = {
                    self: self,
                    super: self.$super,
                    data: {}
                };
                bindings[key] = binding;
            }
            return binding;
        }
    }

    export function enumerateLoadedClasses(...args: (ObjC.EnumerateLoadedClassesCallbacks | ObjC.EnumerateLoadedClassesOptions)[]) {
        const allModules = new ModuleMap();
        let unfiltered = false;

        let callbacks;
        let modules;
        if (args.length === 1) {
            callbacks = <ObjC.EnumerateLoadedClassesCallbacks> args[0];
        } else {
            callbacks = <ObjC.EnumerateLoadedClassesCallbacks> args[1];

            const options = <ObjC.EnumerateLoadedClassesOptions> args[0];
            modules = options.ownedBy;
        }
        if (modules === undefined) {
            modules = allModules;
            unfiltered = true;
        }

        const classGetName = api.class_getName;
        const onMatch = callbacks.onMatch.bind(callbacks);
        const swiftNominalTypeDescriptorOffset = ((pointerSize === 8) ? 8 : 11) * pointerSize;

        const numClasses = <number> api.objc_getClassList(NULL, 0);
        const classHandles = Memory.alloc(numClasses * pointerSize);
        api.objc_getClassList(classHandles, numClasses);

        for (let i = 0; i !== numClasses; i++) {
            const classHandle = classHandles.add(i * pointerSize).readPointer();

            const rawName = <NativePointer> classGetName(classHandle);
            let name = null;

            let modulePath = modules.findPath(rawName);
            const possiblySwift = (modulePath === null) && (unfiltered || allModules.findPath(rawName) === null);
            if (possiblySwift) {
                name = <string> rawName.readUtf8String();
                const probablySwift = name.indexOf('.') !== -1;
                if (probablySwift) {
                    const nominalTypeDescriptor = classHandle.add(swiftNominalTypeDescriptorOffset).readPointer();
                    modulePath = modules.findPath(nominalTypeDescriptor);
                }
            }

            if (modulePath !== null) {
                if (name === null)
                    name = <string> rawName.readUtf8String();
                onMatch(name, modulePath);
            }
        }

        callbacks.onComplete();
    }

    export function enumerateLoadedClassesSync(options: ObjC.EnumerateLoadedClassesOptions = {}) {
        const result = <ObjC.EnumerateLoadedClassesResult> {};
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

    export function choose(specifier: ObjC.ChooseSpecifier, callbacks: EnumerateCallbacks<ObjC.Object>) {
        let cls = specifier;
        let subclasses = <boolean | undefined> true;
        if (!(specifier instanceof Runtime.Object) && typeof specifier === 'object') {
            cls = specifier.class;
            if (specifier.hasOwnProperty('subclasses'))
                subclasses = specifier.subclasses;
        }
        if (!(cls instanceof Runtime.Object && (cls.$kind === 'class' || cls.$kind === 'meta-class')))
            throw new Error("Expected an ObjC.Object for a class or meta-class");

        const matches = getGonzales()
            .choose(cls, subclasses)
            .map((handle: NativePointer) => new Runtime.Object(handle));
        for (const match of matches) {
            const result = callbacks.onMatch(match);
            if (result === 'stop')
                break;
        }

        callbacks.onComplete();
    }

    export function chooseSync(specifier: ObjC.ChooseSpecifier) {
        const instances = <ObjC.Object[]> [];
        choose(specifier, {
            onMatch: function (i) {
                instances.push(i);
            },
            onComplete: function () {
            }
        });
        return instances;
    }

    export function schedule(queue: NativePointerValue, work: () => void) {
        const id = ptr(nextId++);
        scheduledWork[id.toString()] = work;

        if (workCallback === null) {
            workCallback = new NativeCallback(performScheduledWorkItem, 'void', ['pointer']);
        }

        Script.pin();
        api.dispatch_async_f(queue, id, workCallback);
    }

    export function implement(method: ObjC.ObjectMethod, fn: AnyFunction) {
        return new NativeCallback(fn, method.returnType, method.argumentTypes);
    }

    export function selector(name: string) {
        return <NativePointer> api.sel_registerName(Memory.allocUtf8String(name));
    }

    export function selectorAsString(sel: NativePointerValue) {
        return <string> (<NativePointer> api.sel_getName(sel)).readUtf8String();
    }

    const registryBuiltins = new Set([
        "prototype",
        "constructor",
        "hasOwnProperty",
        "toJSON",
        "toString",
        "valueOf"
    ]);

    function ClassRegistry(this: any) {
        const cachedClasses = <Cache<NativePointer>> {};
        let numCachedClasses = 0;

        const registry = new Proxy(this, {
            has(target, property) {
                return hasProperty(property.toString());
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
                        const klass = findClass(property.toString());
                        return (klass !== null) ? klass : undefined;
                }
            },
            set(target, property, value, receiver) {
                return false;
            },
            ownKeys(target) {
                let numClasses = <number> api.objc_getClassList(NULL, 0);
                if (numClasses !== numCachedClasses) {
                    // It's impossible to unregister classes in ObjC, so if the number of
                    // classes hasn't changed, we can assume that the list is up to date.
                    const classHandles = Memory.alloc(numClasses * pointerSize);
                    numClasses = <number> api.objc_getClassList(classHandles, numClasses);
                    for (let i = 0; i !== numClasses; i++) {
                        const handle = classHandles.add(i * pointerSize).readPointer();
                        const ptr = <NativePointer> api.class_getName(handle);
                        const name = <string> ptr.readUtf8String();
                        cachedClasses[name] = handle;

                        // Duktape does not support getOwnPropertyDescriptor yet and checks the target instead:
                        target[name] = true;
                    }
                    numCachedClasses = numClasses;
                }
                return global.Object.keys(cachedClasses);
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: false,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        function hasProperty(name: string) {
            if (registryBuiltins.has(name))
                return true;
            return findClass(name) !== null;
        }

        function getClass(name: string) {
            const cls = findClass(name);
            if (cls === null)
                throw new Error("Unable to find class '" + name + "'");
            return cls;
        }

        function findClass(name: string) {
            let handle = cachedClasses[name];
            if (handle === undefined) {
                handle = <NativePointer> api.objc_lookUpClass(Memory.allocUtf8String(name));
                if (handle.isNull())
                    return null;
                cachedClasses[name] = handle;
                numCachedClasses++;
            }

            return new Runtime.Object(handle, undefined, true);
        }

        function toJSON() {
            return global.Object.keys(registry).reduce(function (r, name) {
                r[name] = getClass(name).toJSON();
                return r;
            }, <any> {});
        }

        function toString() {
            return "ClassRegistry";
        }

        function valueOf() {
            return "ClassRegistry";
        }

        return registry;
    }

    function ProtocolRegistry(this: any) {
        let cachedProtocols = <Cache<NativePointer>> {};
        let numCachedProtocols = 0;

        const registry = new Proxy(this, {
            has(target, property) {
                return hasProperty(property.toString());
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
                        const proto = findProtocol(property.toString());
                        return (proto !== null) ? proto : undefined;
                }
            },
            set(target, property, value, receiver) {
                return false;
            },
            ownKeys(target) {
                const protocolNames = [];
                cachedProtocols = {};

                const numProtocolsBuf = Memory.alloc(pointerSize);
                const protocolHandles = <NativePointer> api.objc_copyProtocolList(numProtocolsBuf);
                try {
                    const numProtocols = numProtocolsBuf.readUInt();
                    if (numProtocols !== numCachedProtocols) {
                        for (let i = 0; i !== numProtocols; i++) {
                            const handle = protocolHandles.add(i * pointerSize).readPointer();
                            const ptr = <NativePointer> api.protocol_getName(handle);
                            const name = <string> ptr.readUtf8String();

                            protocolNames.push(name);
                            cachedProtocols[name] = handle;

                            // Duktape does not support getOwnPropertyDescriptor yet and checks the target instead:
                            target[name] = true;
                        }
                        numCachedProtocols = numProtocols;
                    }
                } finally {
                    api.free(protocolHandles);
                }

                return protocolNames;
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: false,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        function hasProperty(name: string) {
            if (registryBuiltins.has(name))
                return true;
            return findProtocol(name) !== null;
        }

        function findProtocol(name: string) {
            let handle = cachedProtocols[name];
            if (handle === undefined) {
                handle = <NativePointer> api.objc_getProtocol(Memory.allocUtf8String(name));
                if (handle.isNull())
                    return null;
                cachedProtocols[name] = handle;
                numCachedProtocols++;
            }

            return new Runtime.Protocol(handle);
        }

        function toJSON() {
            return global.Object.keys(registry).reduce(function (r, name) {
                r[name] = { handle: cachedProtocols[name] };
                return r;
            }, <any> {});
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

    function ObjCObject(this: ObjC.Object,
                        handle: NativePointer,
                        protocol?: ObjC.Protocol,
                        cachedIsClass?: boolean,
                        superSpecifier?: NativePointer) {
        let cachedClassHandle = <Nullable<NativePointer>> null;
        let cachedKind = <Nullable<string>> null;
        let cachedSuper = <Nullable<Nullable<ObjC.Object>[]>> null;
        let cachedSuperClass = <Nullable<Nullable<ObjC.Object>[]>> null;
        let cachedClass = <Nullable<ObjC.Object>> null;
        let cachedClassName = <Nullable<string>> null;
        let cachedModuleName = <Nullable<string>> null;
        let cachedProtocols = <Nullable<Cache<ObjC.Protocol>>> null;
        let cachedMethodNames = <Nullable<string[]>> null;
        let cachedProtocolMethods = <Nullable<Cache<ProtocolMethodInfo>>> null;
        let respondsToSelector = <Nullable<ObjC.ObjectMethod>> null;
        const cachedMethods = <Cache<ObjectMethodInfo>> {};
        const replacedMethods = <Cache<NativePointer>> {};
        let cachedNativeMethodNames = <Nullable<string[]>> null;
        let cachedOwnMethodNames = <Nullable<string[]>> null;
        let cachedIvars = <Nullable<Cache<any>>> null;
        let weakRef = <Nullable<WeakRefId>> null;

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
                return hasProperty(property.toString());
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
                            const superHandle = <NativePointer> api.class_getSuperclass(classHandle());
                            if (!superHandle.isNull()) {
                                const specifier = Memory.alloc(2 * pointerSize);
                                specifier.writePointer(handle);
                                specifier.add(pointerSize).writePointer(superHandle);
                                cachedSuper = [new Runtime.Object(handle, undefined, cachedIsClass, specifier)];
                            } else {
                                cachedSuper = [null];
                            }
                        }
                        return cachedSuper[0];
                    case "$superClass":
                        if (cachedSuperClass === null) {
                            const superClassHandle = <NativePointer> api.class_getSuperclass(classHandle());
                            if (!superClassHandle.isNull()) {
                                cachedSuperClass = [new Runtime.Object(superClassHandle)];
                            } else {
                                cachedSuperClass = [null];
                            }
                        }
                        return cachedSuperClass[0];
                    case "$class":
                        if (cachedClass === null)
                            cachedClass = new Runtime.Object(<NativePointer> api.object_getClass(handle), undefined, true);
                        return cachedClass;
                    case "$className":
                        if (cachedClassName === null) {
                            if (superSpecifier)
                                cachedClassName = (<NativePointer> api.class_getName(superSpecifier.add(pointerSize).readPointer())).readUtf8String();
                            else if (isClass())
                                cachedClassName = (<NativePointer> api.class_getName(handle)).readUtf8String();
                            else
                                cachedClassName = (<NativePointer> api.object_getClassName(handle)).readUtf8String();
                        }
                        return cachedClassName;
                    case "$moduleName":
                        if (cachedModuleName === null) {
                            cachedModuleName = (<NativePointer> api.class_getImageName(classHandle())).readUtf8String();
                        }
                        return cachedModuleName;
                    case "$protocols":
                        if (cachedProtocols === null) {
                            cachedProtocols = {};
                            const numProtocolsBuf = Memory.alloc(pointerSize);
                            const protocolHandles = <NativePointer> api.class_copyProtocolList(classHandle(), numProtocolsBuf);
                            if (!protocolHandles.isNull()) {
                                try {
                                    const numProtocols = numProtocolsBuf.readUInt();
                                    for (let i = 0; i !== numProtocols; i++) {
                                        const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                                        const p = new Runtime.Protocol(protocolHandle);
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
                            const meta = <NativePointer> api.object_getClass(klass);

                            const names = new Set<string>();

                            let cur = meta;
                            do {
                                for (let methodName of collectMethodNames(cur, "+ "))
                                    names.add(methodName);
                                cur = <NativePointer> api.class_getSuperclass(cur);
                            } while (!cur.isNull());

                            cur = klass;
                            do {
                                for (let methodName of collectMethodNames(cur, "- "))
                                    names.add(methodName);
                                cur = <NativePointer> api.class_getSuperclass(cur);
                            } while (!cur.isNull());

                            cachedNativeMethodNames = Array.from(names);
                        }
                        return cachedNativeMethodNames;
                    case "$ownMethods":
                        if (cachedOwnMethodNames === null) {
                            const klass = superSpecifier ? superSpecifier.add(pointerSize).readPointer() : classHandle();
                            const meta = <NativePointer> api.object_getClass(klass);

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
                                cachedIvars = ObjCIvars(self, classHandle());
                        }
                        return cachedIvars;
                    default:
                        if (typeof property === "symbol") {
                            return target[property.toString()];
                        }
                        if (protocol) {
                            const details = findProtocolMethod(property.toString());
                            if (details === null || !details.implemented)
                                return undefined;
                        }
                        const wrapper = findMethodWrapper(property.toString());
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
                        const jsNames = <Cache<boolean>> {};
                        const nativeNames = <Cache<string>> {};

                        let cur = <NativePointer> api.object_getClass(handle);
                        do {
                            const numMethodsBuf = Memory.alloc(pointerSize);
                            const methodHandles = <NativePointer> api.class_copyMethodList(cur, numMethodsBuf);
                            const fullNamePrefix = isClass() ? "+ " : "- ";
                            try {
                                const numMethods = numMethodsBuf.readUInt();
                                for (let i = 0; i !== numMethods; i++) {
                                    const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                                    const sel = <NativePointer> api.method_getName(methodHandle);
                                    const nativeName = <string> (<NativePointer> api.sel_getName(sel)).readUtf8String();
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

                                    // Duktape does not support getOwnPropertyDescriptor yet and checks the target instead:
                                    target[name] = true;

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
                            cur = <NativePointer> api.class_getSuperclass(cur);
                        } while (!cur.isNull());

                        cachedMethodNames = global.Object.keys(jsNames);
                    } else {
                        const methodNames = <string[]> [];

                        const protocolMethods = allProtocolMethods();
                        global.Object.keys(protocolMethods).forEach(function (methodName) {
                            if (methodName[0] !== '+' && methodName[0] !== '-') {
                                const details = protocolMethods[methodName];
                                if (details.implemented) {
                                    methodNames.push(methodName);

                                    // Duktape does not support getOwnPropertyDescriptor yet and checks the target instead:
                                    target[methodName] = true;
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

        function hasProperty(name: string) {
            if (objCObjectBuiltins.has(name))
                return true;
            if (protocol) {
                const details = findProtocolMethod(name);
                return !!(details !== null && details.implemented);
            }
            return findMethod(name) !== null;
        }

        function findProtocolMethod(rawName: string) {
            const protocolMethods = allProtocolMethods();
            const details = protocolMethods[rawName];
            return (details !== undefined) ? details : null;
        }

        function allProtocolMethods() {
            if (cachedProtocolMethods === null) {
                const methods = <Cache<ProtocolMethodInfo>> {};

                const protocols = collectProtocols(protocol!);
                const defaultKind = isClass() ? '+' : '-';
                global.Object.keys(protocols).forEach(function (name) {
                    const p = protocols[name];
                    const m = p.methods;
                    global.Object.keys(m).forEach(function (fullMethodName) {
                        const method = m[fullMethodName];
                        const methodName = fullMethodName.substr(2);
                        const kind = fullMethodName[0];

                        let didCheckImplemented = false;
                        let implemented = false;
                        const details = {
                            types: method.types,
                            get implemented() {
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
                        };

                        methods[fullMethodName] = details;
                        if (kind === defaultKind)
                            methods[jsMethodName(methodName)] = details;
                    });
                });

                cachedProtocolMethods = methods;
            }

            return cachedProtocolMethods;
        }

        function collectProtocols(p: ObjC.Protocol, acc?: any) {
            acc = acc || {};

            acc[p.name] = p;

            const parentProtocols = p.protocols;
            global.Object.keys(parentProtocols).forEach(function (name) {
                collectProtocols(parentProtocols[name], acc);
            });

            return acc;
        }

        function findMethod(rawName: string) {
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
                        wrapper: null
                    };
                }
            }

            if (method === undefined) {
                const methodHandle = (kind === '+') ?
                    <NativePointer> api.class_getClassMethod(classHandle(), sel) :
                    <NativePointer> api.class_getInstanceMethod(classHandle(), sel);
                if (!methodHandle.isNull()) {
                    method = {
                        sel: sel,
                        handle: methodHandle,
                        wrapper: null
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

                    const methodHandle = <NativePointer> api.class_getInstanceMethod(api.object_getClass(target.handle), sel);
                    if (methodHandle.isNull()) {
                        return null;
                    }
                    let types = (<NativePointer> api.method_getTypeEncoding(methodHandle)).readUtf8String();
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
                        wrapper: null
                    };
                }
            }

            cachedMethods[fullName] = method;
            cachedMethods[rawName] = method;
            if (kind === defaultKind)
                cachedMethods[jsMethodName(name)] = method;

            return method;
        }

        function parseMethodName(rawName: string) {
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

        function objcMethodName(name: string) {
            return name.replace(/_/g, ":");
        }

        function jsMethodName(name: string) {
            let result = name.replace(/:/g, "_");
            if (objCObjectBuiltins.has(result))
                result += "2";
            return result;
        }

        function stealTypesFromProtocols(klass: ObjC.Object, fullName: string) {
            const candidates = global.Object.keys(klass.$protocols)
                .map(protocolName => flatProtocolMethods({}, klass.$protocols[protocolName]))
                .reduce((allMethods, methods) => {
                    global.Object.assign(allMethods, methods);
                    return allMethods;
                }, <Cache<ObjC.ProtocolMethodDescription>> {});

            const method = candidates[fullName];
            if (method === undefined) {
                return null;
            }
            return method.types;
        }

        function flatProtocolMethods(result: Cache<ObjC.ProtocolMethodDescription>,
                                     protocol: ObjC.Protocol) {
            if (protocol.methods !== undefined) {
                global.Object.assign(result, protocol.methods);
            }
            if ((<any> protocol).protocol !== undefined) {
                flatProtocolMethods(result, (<any> protocol).protocol);
            }
            return result;
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

        function classHandle() {
            if (cachedClassHandle === null)
                cachedClassHandle = isClass() ? handle : <NativePointer> api.object_getClass(handle);
            return cachedClassHandle;
        }

        function collectMethodNames(klass: NativePointer, prefix: string) {
            const names = [];

            const numMethodsBuf = Memory.alloc(pointerSize);
            const methodHandles = <NativePointer> api.class_copyMethodList(klass, numMethodsBuf);
            try {
                const numMethods = numMethodsBuf.readUInt();
                for (let i = 0; i !== numMethods; i++) {
                    const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                    const sel = api.method_getName(methodHandle);
                    const nativeName = (<NativePointer> api.sel_getName(sel)).readUtf8String();
                    names.push(prefix + nativeName);
                }
            } finally {
                api.free(methodHandles);
            }

            return names;
        }

        function findMethodWrapper(name: string) {
            const method = findMethod(name);
            if (method === null)
                return null;
            let wrapper = method.wrapper;
            if (wrapper === null) {
                wrapper = makeMethodInvocationWrapper(method, self, superSpecifier, replaceMethodImplementation, defaultInvocationOptions);
                method.wrapper = wrapper;
            }
            return wrapper;
        }

        function replaceMethodImplementation(methodHandle: NativePointer,
                                             imp: NativeFunction,
                                             oldImp: NativePointer) {
            api.method_setImplementation(methodHandle, imp);

            if (!imp.equals(oldImp))
                replacedMethods[methodHandle.toString()] = oldImp;
            else
                delete replacedMethods[methodHandle.toString()];

            if (weakRef === null)
                weakRef = WeakRef.bind(self, dispose);
        }

        function makeMethodInvocationWrapper(method: ObjectMethodInfo,
                                             owner: ObjC.Object,
                                             superSpecifier: NativePointer | undefined,
                                             replaceImplementation: Function,
                                             invocationOptions: NativeFunctionOptions) {
            const sel = method.sel;
            let handle = method.handle;
            let types;
            if (handle === undefined) {
                handle = null;
                types = <string> method.types;
            } else {
                types = <string> (<NativePointer> api.method_getTypeEncoding(handle!)).readUtf8String();
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

            let oldImp = <Nullable<NativePointer>> null;
            let newImp = <Nullable<NativePointer>> null;

            const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " +
                returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
                " }; m;");

            global.Object.defineProperty(m, 'handle', {
                enumerable: true,
                get: getMethodHandle
            });

            m.selector = sel;

            global.Object.defineProperty(m, 'implementation', {
                enumerable: true,
                get: function () {
                    const h = getMethodHandle();

                    return new NativeFunction(<NativePointer> api.method_getImplementation(h),
                        m.returnType, m.argumentTypes, invocationOptions);
                },
                set: function (imp) {
                    const h = getMethodHandle();

                    if (oldImp === null)
                        oldImp = <NativePointer> api.method_getImplementation(h);
                    newImp = imp;

                    replaceImplementation(h, imp, oldImp);
                }
            });

            m.returnType = retType.type;

            m.argumentTypes = signature.argTypes.map(t => t.type);

            m.types = types;

            m.clone = function (options: NativeFunctionOptions) {
                return makeMethodInvocationWrapper(method, owner, superSpecifier, replaceImplementation, options);
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
                                const h = <NativePointer> api.class_getInstanceMethod(target.$class.handle, sel);
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

                return <NativePointer> handle;
            }

            return m;
        }

        function getMsgSendImpl(signature: MethodSignature, invocationOptions: NativeFunctionOptions) {
            return resolveMsgSendImpl(msgSendBySignatureId, signature, invocationOptions, false);
        }

        function getMsgSendSuperImpl(signature: MethodSignature, invocationOptions: NativeFunctionOptions) {
            return resolveMsgSendImpl(msgSendSuperBySignatureId, signature, invocationOptions, true);
        }

        function resolveMsgSendImpl(cache: Cache<NativeFunction>,
                                    signature: MethodSignature,
                                    invocationOptions: NativeFunctionOptions,
                                    isSuper: boolean) {
            if (invocationOptions !== defaultInvocationOptions)
                return makeMsgSendImpl(signature, invocationOptions, isSuper);

            const {id} = signature;

            let impl = cache[id];
            if (impl === undefined) {
                impl = makeMsgSendImpl(signature, invocationOptions, isSuper);
                cache[id] = impl;
            }

            return impl;
        }

        function makeMsgSendImpl(signature: MethodSignature,
                                 invocationOptions: NativeFunctionOptions,
                                 isSuper: boolean) {
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

        function typeFitsInRegisters(type: string | string[]) {
            if (Process.arch !== 'x64')
                return false;

            const size = sizeOfTypeOnX64(type);

            // It's actually way more complex than this, plus, we ignore alignment.
            // But at least we can assume that no SSE types are involved, as we don't yet support them...
            return size <= 16;
        }

        function sizeOfTypeOnX64(type: string | string[]): number {
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

        function dispose() {
            global.Object.keys(replacedMethods).forEach(function (key) {
                const methodHandle = ptr(key);
                const oldImp = replacedMethods[key];
                api.method_setImplementation(methodHandle, oldImp);
            });
        }

        function toJSON() {
            return {
                handle: handle.toString()
            };
        }

        function equals(ptr: any) {
            return handle.equals(getHandle(ptr));
        }
    }

    function ObjCProtocol(this: ObjC.Protocol, handle: NativePointer) {
        let cachedName = <Nullable<string>> null;
        let cachedProtocols = <Nullable<Cache<ObjC.Protocol>>> null;
        let cachedProperties = <Nullable<Cache<ObjC.ProtocolPropertyAttributes>>> null;
        let cachedMethods = <Nullable<Cache<ObjC.ProtocolMethodDescription>>> null;

        this.handle = handle;

        global.Object.defineProperty(this, 'name', {
            get: function () {
                if (cachedName === null)
                    cachedName = (<NativePointer> api.protocol_getName(handle)).readUtf8String();
                return cachedName;
            },
            enumerable: true
        });

        global.Object.defineProperty(this, 'protocols', {
            get: function () {
                if (cachedProtocols === null) {
                    cachedProtocols = {};
                    const numProtocolsBuf = Memory.alloc(pointerSize);
                    const protocolHandles = <NativePointer> api.protocol_copyProtocolList(handle, numProtocolsBuf);
                    if (!protocolHandles.isNull()) {
                        try {
                            const numProtocols = numProtocolsBuf.readUInt();
                            for (let i = 0; i !== numProtocols; i++) {
                                const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                                const protocol = new Runtime.Protocol(protocolHandle);
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

        global.Object.defineProperty(this, 'properties', {
            get: function () {
                if (cachedProperties === null) {
                    cachedProperties = {};
                    const numBuf = Memory.alloc(pointerSize);
                    const propertyHandles = <NativePointer> api.protocol_copyPropertyList(handle, numBuf);
                    if (!propertyHandles.isNull()) {
                        try {
                            const numProperties = numBuf.readUInt();
                            for (let i = 0; i !== numProperties; i++) {
                                const propertyHandle = propertyHandles.add(i * pointerSize).readPointer();
                                const propName = <string> (<NativePointer> api.property_getName(propertyHandle)).readUtf8String();
                                const attributes = <ObjC.ProtocolPropertyAttributes> {};
                                const attributeEntries = <NativePointer> api.property_copyAttributeList(propertyHandle, numBuf);
                                if (!attributeEntries.isNull()) {
                                    try {
                                        const numAttributeValues = numBuf.readUInt();
                                        for (let j = 0; j !== numAttributeValues; j++) {
                                            const attributeEntry = attributeEntries.add(j * (2 * pointerSize));
                                            const name = <string> attributeEntry.readPointer().readUtf8String();
                                            const value = <string> attributeEntry.add(pointerSize).readPointer().readUtf8String();
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

        global.Object.defineProperty(this, 'methods', {
            get: function () {
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

        function collectMethods(methods: Cache<ObjC.ProtocolMethodDescription>,
                                numBuf: NativePointer,
                                spec: any) {
            const methodDescValues = <NativePointer> api.protocol_copyMethodDescriptionList(handle, spec.required ? 1 : 0, spec.instance ? 1 : 0, numBuf);
            if (methodDescValues.isNull())
                return;
            try {
                const numMethodDescValues = numBuf.readUInt();
                for (let i = 0; i !== numMethodDescValues; i++) {
                    const methodDesc = methodDescValues.add(i * (2 * pointerSize));
                    const name = (spec.instance ? '- ' : '+ ') + selectorAsString(methodDesc.readPointer());
                    const types = <string> methodDesc.add(pointerSize).readPointer().readUtf8String();
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

    let blockDescriptorAllocSize: number, blockDescriptorDeclaredSize: number, blockDescriptorOffsets: any;
    let blockSize: number, blockOffsets: any;
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

    interface PrevContext {
        options: NativeFunctionOptions;
        signature: MethodSignature;
        descriptor?: NativePointer;
        typesStr?: NativePointer;
        callback?: NativeCallback;
    }

    interface WithPrevContext {
        [PRIV]: PrevContext;
    }

    function ObjCBlock(this: ObjC.Block & WithPrevContext,
                       target: NativePointer | ObjC.MethodSpec<ObjC.BlockMethodImplementation>,
                       options = defaultInvocationOptions) {
        const priv = <PrevContext> {
            options,
        };
        this[PRIV] = priv;

        if (target instanceof NativePointer) {
            const descriptor = target.add(blockOffsets.descriptor).readPointer();

            this.handle = target;

            const flags = target.add(blockOffsets.flags).readU32();
            if ((flags & BLOCK_HAS_SIGNATURE) !== 0) {
                const signatureOffset = ((flags & BLOCK_HAS_COPY_DISPOSE) !== 0) ? 2 : 0;
                this.types = <string> descriptor.add(blockDescriptorOffsets.rest + (signatureOffset * pointerSize)).readPointer().readCString();
                priv.signature = parseSignature(this.types);
            }
        } else {
            if (!(typeof target === 'object' &&
                    (target.hasOwnProperty('types') || (target.hasOwnProperty('retType') && target.hasOwnProperty('argTypes'))) &&
                    target.hasOwnProperty('implementation'))) {
                throw new Error('Expected type metadata and implementation');
            }

            let types = (<ObjC.DetailedMethodSpec<ObjC.BlockMethodImplementation>> target).types;
            if (types === undefined) {
                const retType = (<ObjC.SimpleMethodSpec<ObjC.BlockMethodImplementation>> target).retType;
                const argTypes = (<ObjC.SimpleMethodSpec<ObjC.BlockMethodImplementation>> target).argTypes;
                types = unparseSignature(retType, ['block'].concat(argTypes));
            }

            const descriptor = Memory.alloc(blockDescriptorAllocSize + blockSize);
            const block = descriptor.add(blockDescriptorAllocSize);
            const typesStr = Memory.allocUtf8String(types);

            descriptor.add(blockDescriptorOffsets.reserved).writeULong(0);
            descriptor.add(blockDescriptorOffsets.size).writeULong(blockDescriptorDeclaredSize);
            descriptor.add(blockDescriptorOffsets.rest).writePointer(typesStr);

            block.add(blockOffsets.isa).writePointer(classRegistry.__NSGlobalBlock__);
            block.add(blockOffsets.flags).writeU32(BLOCK_HAS_SIGNATURE | BLOCK_IS_GLOBAL);
            block.add(blockOffsets.reserved).writeU32(0);
            block.add(blockOffsets.descriptor).writePointer(descriptor);

            this.handle = block;

            priv.descriptor = descriptor;
            this.types = types;
            priv.typesStr = typesStr;
            priv.signature = parseSignature(types);

            this.implementation = target.implementation;
        }

        global.Object.defineProperty(this, 'implementation', {
            enumerable: true,
            get: () => {
                const priv = this[PRIV];
                const address = this.handle.add(blockOffsets.invoke).readPointer();
                const signature = priv.signature;
                return makeBlockInvocationWrapper(this, signature, new NativeFunction(
                    address,
                    signature.retType.type,
                    signature.argTypes.map(function (arg) { return arg.type; }),
                    priv.options));
            },
            set: (func) => {
                const priv = this[PRIV];
                const signature = priv.signature;
                priv.callback = new NativeCallback(
                    makeBlockImplementationWrapper(this, signature, func),
                    signature.retType.type,
                    signature.argTypes.map(function (arg) { return arg.type; }));
                this.handle.add(blockOffsets.invoke).writePointer(priv.callback);
            }
        });

        function makeBlockInvocationWrapper(block: ObjC.Block,
                                            signature: MethodSignature,
                                            implementation: NativeFunction) {
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
            const f = <AnyFunction> eval("var f = function (" + argVariableNames.join(", ") + ") { " +
                returnCaptureLeft + "implementation(this" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
                " }; f;");

            return f.bind(block);
        }

        function makeBlockImplementationWrapper(block: ObjC.Block,
                                                signature: MethodSignature,
                                                implementation: AnyFunction) {
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

            const f = <AnyFunction> eval("var f = function (" + argVariableNames.join(", ") + ") { " +
                "if (!this.handle.equals(handle))" +
                "this.handle = handle;" +
                returnCaptureLeft + "implementation.call(block" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
                " }; f;");

            return f.bind(block);
        }
    }

    function ObjCIvars(this: any, instance: ObjC.Object, classHandle: NativePointer) {
        type IvarsObject = [NativePointer, { get: () => any, set: (value: any) => void } | null];

        const ivars = <Cache<IvarsObject>> {};
        let cachedIvarNames = <Nullable<string[]>> null;

        let classHandles = [];

        let currentClassHandle = classHandle;
        do {
            classHandles.unshift(currentClassHandle);
            currentClassHandle = <NativePointer> api.class_getSuperclass(currentClassHandle);
        } while (!currentClassHandle.isNull());

        const numIvarsBuf = Memory.alloc(pointerSize);
        classHandles.forEach(c => {
            const ivarHandles = <NativePointer> api.class_copyIvarList(c, numIvarsBuf);
            try {
                const numIvars = numIvarsBuf.readUInt();
                for (let i = 0; i !== numIvars; i++) {
                    const handle = ivarHandles.add(i * pointerSize).readPointer();
                    const name = <string> (<NativePointer> api.ivar_getName(handle)).readUtf8String();
                    ivars[name] = [handle, null];
                }
            } finally {
                api.free(ivarHandles);
            }
        });

        const self = new Proxy(this, {
            has(target, property) {
                return hasProperty(property.toString());
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
                        const ivar = findIvar(property.toString());
                        if (ivar === null)
                            return undefined;
                        return ivar.get();
                }
            },
            set(target, property, value, receiver) {
                const ivar = findIvar(property.toString());
                if (ivar === null)
                    throw new Error("Unknown ivar");
                ivar.set(value);
                return true;
            },
            ownKeys(target) {
                if (cachedIvarNames === null) {
                    cachedIvarNames = global.Object.keys(ivars);
                    cachedIvarNames.forEach(name => {
                        // Duktape does not support getOwnPropertyDescriptor yet and checks the target instead:
                        target[name] = true;
                    });
                }

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

        function hasProperty(name: string) {
            if (objCIvarsBuiltins.has(name))
                return true;
            return ivars.hasOwnProperty(name);
        }

        function findIvar(name: string) {
            const entry = ivars[name];
            if (entry === undefined)
                return null;
            let impl = entry[1];
            if (impl === null) {
                const ivar = entry[0];

                const offset = (<NativePointer> api.ivar_getOffset(ivar)).toInt32();
                const address = instance.handle.add(offset);

                const type = parseType(<string> (<NativePointer> api.ivar_getTypeEncoding(ivar)).readUtf8String());
                const fromNative = type.fromNative || identityTransform;
                const toNative = type.toNative || identityTransform;

                let read: (p: NativePointer) => NativePointer;
                let write: (p: NativePointer, v: any) => void;
                if (name === 'isa') {
                    read = readObjectIsa!;
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

        function toJSON() {
            return global.Object.keys(self).reduce(function (result, name) {
                result[name] = self[name];
                return result;
            }, <any> {});
        }

        function toString() {
            return "ObjCIvars";
        }

        function valueOf() {
            return "ObjCIvars";
        }
    }

    function getHandle(obj: ObjC.Object | NativePointer) {
        if (obj instanceof NativePointer)
            return obj;
        else if (typeof obj === 'object' && obj.hasOwnProperty('handle'))
            return obj.handle;
        else
            throw new Error("Expected NativePointer or ObjC.Object instance");
    }

    if (available) {
        const isaMasks = <any> {
            x64: '0x7ffffffffff8',
            arm64: '0xffffffff8'
        };

        const rawMask = isaMasks[Process.arch];
        if (rawMask !== undefined) {
            const mask = ptr(rawMask);
            readObjectIsa = function (p: NativePointer) {
                return p.readPointer().and(mask);
            };
        } else {
            readObjectIsa = function (p: NativePointer) {
                return p.readPointer();
            };
        }
    }

    function unparseSignature(retType: string | TypeDescription,
                              argTypes: (string | TypeDescription)[]) {
        const frameSize = argTypes.length * pointerSize;
        return typeIdFromAlias(retType) + frameSize + argTypes.map(function (argType, i) {
            const frameOffset = (i * pointerSize);
            return typeIdFromAlias(argType) + frameOffset;
        }).join("");
    }

    function parseSignature(sig: string) {
        const cursor = <[string, number]> [sig, 0];

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

        return <MethodSignature> {
            id: id,
            retType: retType,
            argTypes: argTypes
        };
    }

    function parseType(type: string) {
        const cursor = <[string, number]> [type, 0];

        return readType(cursor);
    }

    function readType(cursor: [string, number]): TypeDescription {
        let id = readChar(cursor);
        if (id === '@') {
            let next = peekChar(cursor);
            if (next === '?') {
                id += next;
                skipChar(cursor);
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

        const type = singularTypeById![id];
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
            return singularTypeById!['i'];
        } else if (id === '^') {
            readType(cursor);
            return singularTypeById!['?'];
        } else {
            throw new Error("Unable to handle type " + id);
        }
    }

    function readNumber(cursor: [string, number]) {
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

    function readUntil(token: string, cursor: [string, number]) {
        const buffer = cursor[0];
        const offset = cursor[1];
        const index = buffer.indexOf(token, offset);
        if (index === -1)
            throw new Error("Expected token '" + token + "' not found");
        const result = buffer.substring(offset, index);
        cursor[1] = index + 1;
        return result;
    }

    function readChar(cursor: [string, number]) {
        return cursor[0][cursor[1]++];
    }

    function peekChar(cursor: [string, number]) {
        return cursor[0][cursor[1]];
    }

    function tokenExistsAhead(token: string, terminator: string, cursor: [string, number]) {
        const [buffer, offset] = cursor;

        const tokenIndex = buffer.indexOf(token, offset);
        if (tokenIndex === -1)
            return false;

        const terminatorIndex = buffer.indexOf(terminator, offset);
        if (terminatorIndex === -1)
            throw new Error("Expected to find terminator: " + terminator);

        return tokenIndex < terminatorIndex;
    }

    function skipChar(cursor: [string, number]) {
        cursor[1]++;
    }

    function dataAvailable(cursor: [string, number]) {
        return cursor[1] !== cursor[0].length;
    }

    const qualifierById = <Cache<string>> {
        'r': 'const',
        'n': 'in',
        'N': 'inout',
        'o': 'out',
        'O': 'bycopy',
        'R': 'byref',
        'V': 'oneway'
    };

    function parseQualifiers(cursor: [string, number]) {
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

    const idByAlias = <Cache<string>> {
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

    function typeIdFromAlias(alias: string | TypeDescription) {
        if (typeof alias === 'object' && alias !== null)
            return `@"${alias.type}"`;

        const id = idByAlias[alias];
        if (id === undefined)
            throw new Error("No known encoding for type " + alias);
        return id;
    }

    const fromNativeId = function (this: any, h: NativePointer) {
        if (h.isNull()) {
            return null;
        } else if (h.toString(16) === this.handle.toString(16)) {
            return this;
        } else {
            return new Runtime.Object(h);
        }
    };

    const toNativeId = function (v: any) {
        if (v === null)
            return NULL;

        const type = typeof v;
        if (type === 'string') {
            if (cachedNSStringCtor === null) {
                cachedNSString = classRegistry.NSString;
                cachedNSStringCtor = <ObjC.ObjectMethod> cachedNSString.stringWithUTF8String_;
            }
            return cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(v));
        } else if (type === 'number') {
            if (cachedNSNumberCtor === null) {
                cachedNSNumber = classRegistry.NSNumber;
                cachedNSNumberCtor = <ObjC.ObjectMethod> cachedNSNumber.numberWithDouble_;
            }
            return cachedNSNumberCtor.call(cachedNSNumber, v);
        }

        return v;
    };

    const fromNativeBlock = function (this: any, h: NativePointer) {
        if (h.isNull()) {
            return null;
        } else if (h.toString(16) === this.handle.toString(16)) {
            return this;
        } else {
            return new Runtime.Block(h);
        }
    };

    const toNativeBlock = function (v: any) {
        return (v !== null) ? v : NULL;
    };

    const toNativeObjectArray = function (v: any) {
        if (v instanceof Array) {
            const length = v.length;
            const array = Memory.alloc(length * pointerSize);
            for (let i = 0; i !== length; i++)
                array.add(i * pointerSize).writePointer(toNativeId(v[i]));
            return array;
        }

        return v;
    };

    function arrayType(length: number, elementType: TypeDescription) {
        return <TypeDescription> {
            type: 'pointer',
            read: function (address: NativePointer) {
                const result = [];

                const elementSize = elementType.size;
                for (let index = 0; index !== length; index++) {
                    result.push(elementType.read(address.add(index * elementSize)));
                }

                return result;
            },
            write: function (address: NativePointer, values: any[]) {
                const elementSize = elementType.size;
                values.forEach((value, index) => {
                    elementType.write(address.add(index * elementSize), value);
                });
            }
        };
    }

    function structType(fieldTypes: TypeDescription[]) {
        let fromNative, toNative;

        if (fieldTypes.some(function (t) { return !!t.fromNative; })) {
            const fromTransforms = fieldTypes.map((t) => {
                if (t.fromNative)
                    return t.fromNative;
                else
                    return identityTransform;
            });
            fromNative = function (this: any, v: NativeReturnValue[]) {
                return v.map((e, i) => {
                    return fromTransforms[i].call(this, e);
                });
            };
        } else {
            fromNative = identityTransform;
        }

        if (fieldTypes.some(function (t) { return !!t.toNative; })) {
            const toTransforms = fieldTypes.map((t) => {
                if (t.toNative)
                    return t.toNative;
                else
                    return identityTransform;
            });
            toNative = function (this: any, v: NativeReturnValue[]) {
                return v.map((e, i) => {
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
        }, [0, <number[]> []]);

        return <TypeDescription> {
            type: fieldTypes.map(t => t.type),
            size: totalSize,
            read: function (address: NativePointer) {
                return fieldTypes.map((type, index) => type.read(address.add(fieldOffsets[index])));
            },
            write: function (address: NativePointer, values: any[]) {
                values.forEach((value, index) => {
                    fieldTypes[index].write(address.add(fieldOffsets[index]), value);
                });
            },
            fromNative: fromNative,
            toNative: toNative
        };
    }

    function unionType(fieldTypes: TypeDescription[]) {
        const largestType = fieldTypes.reduce(function (largest, t) {
            if (t.size > largest.size)
                return t;
            else
                return largest;
        }, fieldTypes[0]);

        let fromNative, toNative;

        if (largestType.fromNative) {
            const fromTransform = largestType.fromNative;
            fromNative = function (this: any, v: NativePointer[]) {
                return fromTransform.call(this, v[0]);
            };
        } else {
            fromNative = function (v: NativePointer[]) {
                return v[0];
            };
        }

        if (largestType.toNative) {
            const toTransform = largestType.toNative;
            toNative = function (this: any, v: any) {
                return [toTransform.call(this, v)];
            };
        } else {
            toNative = function (v: any) {
                return [v];
            };
        }

        return <TypeDescription> {
            type: [largestType.type],
            size: largestType.size,
            read: largestType.read,
            write: largestType.write,
            fromNative: fromNative,
            toNative: toNative
        };
    }

    const longBits = (pointerSize == 8 && Process.platform !== 'windows') ? 64 : 32;

    singularTypeById = <Cache<TypeDescription>> {
        'c': {
            type: 'char',
            size: 1,
            read: address => address.readS8(),
            write: (address, value) => { address.writeS8(value); },
            toNative: function (v) {
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
            fromNative: function (v) {
                return v ? true : false;
            },
            toNative: function (v) {
                return v ? 1 : 0;
            }
        },
        'v': <TypeDescription> {
            type: 'void',
            size: 0
        },
        '*': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative: function (h: NativePointer) {
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

    function identityTransform(v: any) {
        return v;
    }

    function align(value: number, boundary: number) {
        const remainder = value % boundary;
        return (remainder === 0) ? value : value + (boundary - remainder);
    }

    function performScheduledWorkItem(rawId: NativePointer) {
        const id = rawId.toString();
        const work = scheduledWork[id];
        delete scheduledWork[id];

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

    function performScheduledWorkCleanup(pendingException: Error | null) {
        Script.unpin();

        if (pendingException !== null) {
            throw pendingException;
        }
    }
}
