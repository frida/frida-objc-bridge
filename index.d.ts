declare module "frida-objc-bridge" {
    namespace ObjC {
        /**
         * Whether the current process has an Objective-C runtime loaded. Do not invoke any other ObjC properties or
         * methods unless this is the case.
         */
        const available: boolean;

        /**
         * Direct access to a big portion of the Objective-C runtime API.
         */
        const api: {
            [name: string]: any;
        };

        /**
         * Dynamically generated bindings for each of the currently registered classes.
         *
         * You can interact with objects by using dot notation and replacing colons with underscores, i.e.:
         *
         * ```
         *     [NSString stringWithString:@"Hello World"];
         * ```
         *
         * becomes:
         *
         * ```
         *     const NSString = ObjC.classes.NSString;
         *     NSString.stringWithString_("Hello World");
         * ```
         *
         * Note the underscore after the method name.
         */
        const classes: {
            [name: string]: ObjC.Object;
        };

        /**
         * Dynamically generated bindings for each of the currently registered protocols.
         */
        const protocols: {
            [name: string]: Protocol;
        };

        /**
         * GCD queue of the main thread.
         */
        const mainQueue: NativePointer;

        /**
         * Schedule the JavaScript function `work` on the GCD queue specified by `queue`. An NSAutoreleasePool is created
         * just before calling `work`, and cleaned up on return.
         *
         * E.g. on macOS:
         * ```
         *     const { NSSound } = ObjC.classes;
         *     ObjC.schedule(ObjC.mainQueue, () => {
         *         const sound = NSSound.alloc().initWithContentsOfFile_byReference_("/Users/oleavr/.Trash/test.mp3", true).autorelease();
         *         sound.play();
         *     });
         * ```
         *
         * @param queue GCD queue to schedule `work` on.
         * @param work Function to call on the specified `queue`.
         */
        function schedule(queue: NativePointerValue, work: () => void): void;

        /**
         * Dynamically generated wrapper for any Objective-C instance, class, or meta-class.
         */
        class Object implements ObjectWrapper, ObjectMethods {
            constructor(handle: NativePointer, protocol?: Protocol);

            handle: NativePointer;

            /**
             * Whether this is an instance, class, or meta-class.
             */
            $kind: ObjectKind;

            /**
             * Instance used for chaining up to super-class method implementations.
             */
            $super: ObjC.Object;

            /**
             * Super-class of this object's class.
             */
            $superClass: ObjC.Object;

            /**
             * Class that this object is an instance of.
             */
            $class: ObjC.Object;

            /**
             * Class name of this object.
             */
            $className: string;

            /**
             * Name of module where this object is implemented.
             */
            $moduleName: string;

            /**
             * Protocols that this object conforms to.
             */
            $protocols: {
                [name: string]: Protocol;
            };

            /**
             * Native method names exposed by this object’s class and parent classes.
             */
            $methods: string[];

            /**
             * Native method names exposed by this object’s class, not including parent classes.
             */
            $ownMethods: string[];

            /**
             * Instance variables on this object. Supports both access and assignment.
             */
            $ivars: {
                [name: string]: any;
            };

            /**
             * Determines whether two instances refer to the same underlying object.
             *
             * @param other Other object instance or address to compare to.
             */
            equals(other: ObjC.Object | NativePointer): boolean;

            [name: string]: any;
        }

        interface ObjectMethods {
            [name: string]: ObjectMethod;
        }

        interface ObjectMethod extends ObjectWrapper, AnyFunction {
            handle: NativePointer;

            /**
             * Objective-C selector. Use `ObjC.selectorAsString()` to convert it to a string.
             */
            selector: NativePointer;

            /**
             * Current implementation.
             *
             * You may replace it by assigning to this property. See `ObjC.implement()` for details.
             */
            implementation: NativePointer;

            /**
             * Return type name.
             */
            returnType: string;

            /**
             * Argument type names.
             */
            argumentTypes: string[];

            /**
             * Signature.
             */
            types: string;

            /**
             * Makes a new method wrapper with custom NativeFunction options.
             *
             * Useful for e.g. setting `traps: "all"` to perform execution tracing
             * in conjunction with Stalker.
             */
            clone: (options: NativeFunctionOptions) => ObjectMethod;
        }

        /**
         * What kind of object an ObjC.Object represents.
         */
        type ObjectKind = "instance" | "class" | "meta-class";

        /**
         * Dynamically generated language binding for any Objective-C protocol.
         */
        class Protocol implements ObjectWrapper {
            constructor(handle: NativePointer);

            handle: NativePointer;

            /**
             * Name visible to the Objective-C runtime.
             */
            name: string;

            /**
             * Protocols that this protocol conforms to.
             */
            protocols: {
                [name: string]: Protocol;
            };

            /**
             * Properties declared by this protocol.
             */
            properties: {
                [name: string]: ProtocolPropertyAttributes;
            };

            /**
             * Methods declared by this protocol.
             */
            methods: {
                [name: string]: ProtocolMethodDescription;
            };
        }

        interface ProtocolPropertyAttributes {
            [name: string]: string;
        }

        interface ProtocolMethodDescription {
            /**
             * Whether this method is required or optional.
             */
            required: boolean;

            /**
             * Method signature.
             */
            types: string;
        }

        /**
         * Dynamically generated language binding for any Objective-C block.
         *
         * Also supports implementing a block from scratch by passing in an
         * implementation.
         */
        class Block implements ObjectWrapper {
            constructor(target: NativePointer | MethodSpec<BlockImplementation>, options?: NativeFunctionOptions);

            handle: NativePointer;

            /**
             * Signature, if available.
             */
            types?: string | undefined;

            /**
             * Current implementation. You may replace it by assigning to this property.
             */
            implementation: AnyFunction;

            /**
             * Declares the signature of an externally defined block. This is needed
             * when working with blocks without signature metadata, i.e. when
             * `block.types === undefined`.
             *
             * @param signature Signature to use.
             */
            declare(signature: BlockSignature): void;
        }

        type BlockImplementation = (this: Block, ...args: any[]) => any;

        type BlockSignature = SimpleBlockSignature | DetailedBlockSignature;

        interface SimpleBlockSignature {
            /**
             * Return type.
             */
            retType: string;

            /**
             * Argument types.
             */
            argTypes: string[];
        }

        interface DetailedBlockSignature {
            /**
             * Signature.
             */
            types: string;
        }

        /**
         * Creates a JavaScript implementation compatible with the signature of `method`, where `fn` is used as the
         * implementation. Returns a `NativeCallback` that you may assign to an ObjC method’s `implementation` property.
         *
         * @param method Method to implement.
         * @param fn Implementation.
         */
        function implement(method: ObjectMethod, fn: AnyFunction): NativeCallback<any, any>;

        /**
         * Creates a new class designed to act as a proxy for a target object.
         *
         * @param spec Proxy specification.
         */
        function registerProxy(spec: ProxySpec): ProxyConstructor;

        /**
         * Creates a new Objective-C class.
         *
         * @param spec Class specification.
         */
        function registerClass(spec: ClassSpec): ObjC.Object;

        /**
         * Creates a new Objective-C protocol.
         *
         * @param spec Protocol specification.
         */
        function registerProtocol(spec: ProtocolSpec): Protocol;

        /**
         * Binds some JavaScript data to an Objective-C instance.
         *
         * @param obj Objective-C instance to bind data to.
         * @param data Data to bind.
         */
        function bind(obj: ObjC.Object | NativePointer, data: InstanceData): void;

        /**
         * Unbinds previously associated JavaScript data from an Objective-C instance.
         *
         * @param obj Objective-C instance to unbind data from.
         */
        function unbind(obj: ObjC.Object | NativePointer): void;

        /**
         * Looks up previously bound data from an Objective-C object.
         *
         * @param obj Objective-C instance to look up data for.
         */
        function getBoundData(obj: ObjC.Object | NativePointer): any;

        /**
         * Enumerates loaded classes.
         *
         * @param callbacks Object with callbacks.
         */
        function enumerateLoadedClasses(callbacks: EnumerateLoadedClassesCallbacks): void;

        /**
         * Enumerates loaded classes.
         *
         * @param options Options customizing the enumeration.
         * @param callbacks Object with callbacks.
         */
        function enumerateLoadedClasses(
            options: EnumerateLoadedClassesOptions,
            callbacks: EnumerateLoadedClassesCallbacks,
        ): void;

        /**
         * Synchronous version of `enumerateLoadedClasses()`.
         *
         * @param options Options customizing the enumeration.
         */
        function enumerateLoadedClassesSync(options?: EnumerateLoadedClassesOptions): EnumerateLoadedClassesResult;

        interface EnumerateLoadedClassesOptions {
            /**
             * Limit enumeration to modules in the given module map.
             */
            ownedBy?: ModuleMap | undefined;
        }

        interface EnumerateLoadedClassesCallbacks {
            onMatch: (name: string, owner: string) => void;
            onComplete: () => void;
        }

        interface EnumerateLoadedClassesResult {
            /**
             * Class names grouped by name of owner module.
             */
            [owner: string]: string[];
        }

        function choose(specifier: ChooseSpecifier, callbacks: EnumerateCallbacks<ObjC.Object>): void;

        /**
         * Synchronous version of `choose()`.
         *
         * @param specifier What kind of objects to look for.
         */
        function chooseSync(specifier: ChooseSpecifier): ObjC.Object[];

        /**
         * Converts the JavaScript string `name` to a selector.
         *
         * @param name Name to turn into a selector.
         */
        function selector(name: string): NativePointer;

        /**
         * Converts the selector `sel` to a JavaScript string.
         *
         * @param sel Selector to turn into a string.
         */
        function selectorAsString(sel: NativePointerValue): string;

        interface ProxySpec<D extends ProxyData = ProxyData, T = ObjC.Object, S = ObjC.Object> {
            /**
             * Name of the proxy class.
             *
             * Omit this if you don’t care about the globally visible name and would like the runtime to auto-generate one
             * for you.
             */
            name?: string | undefined;

            /**
             * Protocols this proxy class conforms to.
             */
            protocols?: Protocol[] | undefined;

            /**
             * Methods to implement.
             */
            methods?: {
                [name: string]: UserMethodImplementation<D, T, S> | MethodSpec<UserMethodImplementation<D, T, S>>;
            } | undefined;

            /**
             * Callbacks for getting notified about events.
             */
            events?: ProxyEventCallbacks<D, T, S> | undefined;
        }

        interface ProxyEventCallbacks<D, T, S> {
            /**
             * Gets notified right after the object has been deallocated.
             *
             * This is where you might clean up any associated state.
             */
            dealloc?(this: UserMethodInvocation<D, T, S>): void;

            /**
             * Gets notified about the method name that we’re about to forward
             * a call to.
             *
             * This might be where you’d start out with a temporary callback
             * that just logs the names to help you decide which methods to
             * override.
             *
             * @param name Name of method that is about to get called.
             */
            forward?(this: UserMethodInvocation<D, T, S>, name: string): void;
        }

        /**
         * Constructor for instantiating a proxy object.
         *
         * @param target Target object to proxy to.
         * @param data Object with arbitrary data.
         */
        interface ProxyConstructor {
            new(target: ObjC.Object | NativePointer, data?: InstanceData): ProxyInstance;
        }

        interface ProxyInstance {
            handle: NativePointer;
        }

        interface ProxyData extends InstanceData {
            /**
             * This proxy's target object.
             */
            target: ObjC.Object;

            /**
             * Used by the implementation.
             */
            events: {};
        }

        interface ClassSpec<D = InstanceData, T = ObjC.Object, S = ObjC.Object> {
            /**
             * Name of the class.
             *
             * Omit this if you don’t care about the globally visible name and would like the runtime to auto-generate one
             * for you.
             */
            name?: string | undefined;

            /**
             * Super-class, or `null` to create a new root class. Omit to inherit from `NSObject`.
             */
            super?: ObjC.Object | null | undefined;

            /**
             * Protocols this class conforms to.
             */
            protocols?: Protocol[] | undefined;

            /**
             * Methods to implement.
             */
            methods?: {
                [name: string]: UserMethodImplementation<D, T, S> | MethodSpec<UserMethodImplementation<D, T, S>>;
            } | undefined;
        }

        type MethodSpec<I> = SimpleMethodSpec<I> | DetailedMethodSpec<I>;

        interface SimpleMethodSpec<I> {
            /**
             * Return type.
             */
            retType: string;

            /**
             * Argument types.
             */
            argTypes: string[];

            /**
             * Implementation.
             */
            implementation: I;
        }

        interface DetailedMethodSpec<I> {
            /**
             * Signature.
             */
            types: string;

            /**
             * Implementation.
             */
            implementation: I;
        }

        type UserMethodImplementation<D, T, S> = (this: UserMethodInvocation<D, T, S>, ...args: any[]) => any;

        interface UserMethodInvocation<D, T, S> {
            self: T;
            super: S;
            data: D;
        }

        /**
         * User-defined data that can be accessed from method implementations.
         */
        interface InstanceData {
            [name: string]: any;
        }

        interface ProtocolSpec {
            /**
             * Name of the protocol.
             *
             * Omit this if you don’t care about the globally visible name and would like the runtime to auto-generate one
             * for you.
             */
            name?: string | undefined;

            /**
             * Protocols this protocol conforms to.
             */
            protocols?: Protocol[] | undefined;

            methods?: {
                [name: string]: ProtocolMethodSpec;
            } | undefined;
        }

        type ProtocolMethodSpec = SimpleProtocolMethodSpec | DetailedProtocolMethodSpec;

        interface SimpleProtocolMethodSpec {
            /**
             * Return type.
             */
            retType: string;

            /**
             * Argument types.
             */
            argTypes: string[];

            /**
             * Whether this method is required or optional. Default is required.
             */
            optional?: boolean | undefined;
        }

        interface DetailedProtocolMethodSpec {
            /**
             * Method signature.
             */
            types: string;

            /**
             * Whether this method is required or optional. Default is required.
             */
            optional?: boolean | undefined;
        }

        type ChooseSpecifier = SimpleChooseSpecifier | DetailedChooseSpecifier;

        type SimpleChooseSpecifier = ObjC.Object;

        interface DetailedChooseSpecifier {
            /**
             * Which class to look for instances of. E.g.: `ObjC.classes.UIButton`.
             */
            class: ObjC.Object;

            /**
             * Whether you’re also interested in subclasses matching the given class selector.
             *
             * The default is to also include subclasses.
             */
            subclasses?: boolean | undefined;
        }
    }

    export default ObjC;
}
