let cachedApi = null;

export const defaultInvocationOptions = {
    exceptions: 'propagate'
};

export function getApi() {
    if (cachedApi !== null) {
        return cachedApi;
    }

    const temporaryApi = {};
    const pending = [
        {
            module: "libsystem_malloc.dylib",
            functions: {
                "free": ['void', ['pointer']]
            }
        }, {
            module: "libobjc.A.dylib",
            functions: {
                "objc_msgSend": function (address) {
                    this.objc_msgSend = address;
                },
                "objc_msgSend_stret": function (address) {
                    this.objc_msgSend_stret = address;
                },
                "objc_msgSend_fpret": function (address) {
                    this.objc_msgSend_fpret = address;
                },
                "objc_msgSendSuper": function (address) {
                    this.objc_msgSendSuper = address;
                },
                "objc_msgSendSuper_stret": function (address) {
                    this.objc_msgSendSuper_stret = address;
                },
                "objc_msgSendSuper_fpret": function (address) {
                    this.objc_msgSendSuper_fpret = address;
                },
                "objc_getClassList": ['int', ['pointer', 'int']],
                "objc_lookUpClass": ['pointer', ['pointer']],
                "objc_allocateClassPair": ['pointer', ['pointer', 'pointer', 'pointer']],
                "objc_disposeClassPair": ['void', ['pointer']],
                "objc_registerClassPair": ['void', ['pointer']],
                "class_isMetaClass": ['bool', ['pointer']],
                "class_getName": ['pointer', ['pointer']],
                "class_getImageName": ['pointer', ['pointer']],
                "class_copyProtocolList": ['pointer', ['pointer', 'pointer']],
                "class_copyMethodList": ['pointer', ['pointer', 'pointer']],
                "class_getClassMethod": ['pointer', ['pointer', 'pointer']],
                "class_getInstanceMethod": ['pointer', ['pointer', 'pointer']],
                "class_getSuperclass": ['pointer', ['pointer']],
                "class_addProtocol": ['bool', ['pointer', 'pointer']],
                "class_addMethod": ['bool', ['pointer', 'pointer', 'pointer', 'pointer']],
                "class_copyIvarList": ['pointer', ['pointer', 'pointer']],
                "objc_getProtocol": ['pointer', ['pointer']],
                "objc_copyProtocolList": ['pointer', ['pointer']],
                "objc_allocateProtocol": ['pointer', ['pointer']],
                "objc_registerProtocol": ['void', ['pointer']],
                "protocol_getName": ['pointer', ['pointer']],
                "protocol_copyMethodDescriptionList": ['pointer', ['pointer', 'bool', 'bool', 'pointer']],
                "protocol_copyPropertyList": ['pointer', ['pointer', 'pointer']],
                "protocol_copyProtocolList": ['pointer', ['pointer', 'pointer']],
                "protocol_addProtocol": ['void', ['pointer', 'pointer']],
                "protocol_addMethodDescription": ['void', ['pointer', 'pointer', 'pointer', 'bool', 'bool']],
                "ivar_getName": ['pointer', ['pointer']],
                "ivar_getTypeEncoding": ['pointer', ['pointer']],
                "ivar_getOffset": ['pointer', ['pointer']],
                "object_isClass": ['bool', ['pointer']],
                "object_getClass": ['pointer', ['pointer']],
                "object_getClassName": ['pointer', ['pointer']],
                "method_getName": ['pointer', ['pointer']],
                "method_getTypeEncoding": ['pointer', ['pointer']],
                "method_getImplementation": ['pointer', ['pointer']],
                "method_setImplementation": ['pointer', ['pointer', 'pointer']],
                "property_getName": ['pointer', ['pointer']],
                "property_copyAttributeList": ['pointer', ['pointer', 'pointer']],
                "sel_getName": ['pointer', ['pointer']],
                "sel_registerName": ['pointer', ['pointer']],
                "class_getInstanceSize": ['pointer', ['pointer']]
            },
            optionals: {
                "objc_msgSend_stret": 'ABI',
                "objc_msgSend_fpret": 'ABI',
                "objc_msgSendSuper_stret": 'ABI',
                "objc_msgSendSuper_fpret": 'ABI',
                "object_isClass": 'iOS8'
            }
        }, {
            module: "libdispatch.dylib",
            functions: {
                "dispatch_async_f": ['void', ['pointer', 'pointer', 'pointer']]
            },
            variables: {
                "_dispatch_main_q": function (address) {
                    this._dispatch_main_q = address;
                }
            }
        }
    ];
    let remaining = 0;
    pending.forEach(function (api) {
        const isObjCApi = api.module === 'libobjc.A.dylib';
        const functions = api.functions || {};
        const variables = api.variables || {};
        const optionals = api.optionals || {};

        remaining += Object.keys(functions).length + Object.keys(variables).length;

        const exportByName = (Process.findModuleByName(api.module)?.enumerateExports() ?? [])
        .reduce(function (result, exp) {
            result[exp.name] = exp;
            return result;
        }, {});

        Object.keys(functions)
        .forEach(function (name) {
            const exp = exportByName[name];
            if (exp !== undefined && exp.type === 'function') {
                const signature = functions[name];
                if (typeof signature === 'function') {
                    signature.call(temporaryApi, exp.address);
                    if (isObjCApi)
                        signature.call(temporaryApi, exp.address);
                } else {
                    temporaryApi[name] = new NativeFunction(exp.address, signature[0], signature[1], defaultInvocationOptions);
                    if (isObjCApi)
                        temporaryApi[name] = temporaryApi[name];
                }
                remaining--;
            } else {
                const optional = optionals[name];
                if (optional)
                    remaining--;
            }
        });

        Object.keys(variables)
        .forEach(function (name) {
            const exp = exportByName[name];
            if (exp !== undefined && exp.type === 'variable') {
                const handler = variables[name];
                handler.call(temporaryApi, exp.address);
                remaining--;
            }
        });
    });
    if (remaining === 0) {
        if (!temporaryApi.objc_msgSend_stret)
            temporaryApi.objc_msgSend_stret = temporaryApi.objc_msgSend;
        if (!temporaryApi.objc_msgSend_fpret)
            temporaryApi.objc_msgSend_fpret = temporaryApi.objc_msgSend;
        if (!temporaryApi.objc_msgSendSuper_stret)
            temporaryApi.objc_msgSendSuper_stret = temporaryApi.objc_msgSendSuper;
        if (!temporaryApi.objc_msgSendSuper_fpret)
            temporaryApi.objc_msgSendSuper_fpret = temporaryApi.objc_msgSendSuper;

        cachedApi = temporaryApi;
    }

    return cachedApi;
}
