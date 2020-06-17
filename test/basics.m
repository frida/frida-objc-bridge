/*
 * Copyright (C) 2015-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#define SUITE "/Basics"
#include "fixture.m"

TESTLIST_BEGIN (basics)
  TESTENTRY (classes_can_be_enumerated)
  TESTENTRY (protocols_can_be_enumerated)
  TESTENTRY (object_enumeration_should_contain_parent_methods)
  TESTENTRY (object_enumeration_should_contain_protocol_methods)
  TESTENTRY (class_enumeration_should_not_contain_instance_methods)
  TESTENTRY (instance_enumeration_should_not_contain_class_methods)
  TESTENTRY (class_can_be_retrieved)
  TESTENTRY (kind_can_be_retrieved)
  TESTENTRY (super_can_be_retrieved)
  TESTENTRY (class_name_can_be_retrieved)
  TESTENTRY (module_name_can_be_retrieved)
  TESTENTRY (protocols_can_be_retrieved)
  TESTENTRY (all_method_names_can_be_retrieved)
  TESTENTRY (own_method_names_can_be_retrieved)
  TESTENTRY (ivars_can_be_accessed)
  TESTENTRY (class_method_can_be_invoked)
  TESTENTRY (object_can_be_constructed_from_pointer)
  TESTENTRY (string_can_be_constructed)
  TESTENTRY (string_can_be_passed_as_argument)
  TESTENTRY (class_can_be_implemented)

  TESTGROUP_BEGIN ("Block")
    TESTENTRY (block_can_be_implemented)
    TESTENTRY (block_can_be_invoked)
    TESTENTRY (block_can_be_traced_while_invoked)
    TESTENTRY (block_can_be_migrated_to_the_heap_behind_our_back)
    TESTENTRY (block_without_signature_can_be_used_after_calling_declare)
  TESTGROUP_END ()

  TESTENTRY (basic_method_implementation_can_be_overridden)
  TESTENTRY (struct_consuming_method_implementation_can_be_overridden)
  TESTENTRY (struct_returning_method_can_be_called)
  TESTENTRY (floating_point_returning_method_can_be_called)
  TESTENTRY (attempt_to_read_inexistent_property_should_yield_undefined)
  TESTENTRY (proxied_method_can_be_invoked)
  TESTENTRY (proxied_method_can_be_overridden)
  TESTENTRY (methods_with_weird_names_can_be_invoked)
  TESTENTRY (method_call_preserves_value)
  TESTENTRY (method_call_can_be_traced)
  TESTENTRY (objects_can_be_serialized_to_json)

  TESTGROUP_BEGIN ("EnumerateLoadedClasses")
    TESTENTRY (classes_can_be_enumerated_without_filtering)
    TESTENTRY (classes_can_be_enumerated_with_filtering)
    TESTENTRY (swift_classes_can_be_enumerated)
  TESTGROUP_END ()

  TESTENTRY (existing_instances_can_be_discovered)
  TESTENTRY (function_can_be_scheduled_on_a_dispatch_queue)
  TESTENTRY (performance)
TESTLIST_END ()

@protocol FridaCalculator
- (int)add:(int)value;
- (void)add:(int)value completion:(void (^)(int, NSError *))block;
- (void)addSquared:(int)value completion:(void (^)(int, void *))block;
- (int)sub:(int)value;
@optional
- (int)magic;
@end

@interface FridaDefaultCalculator : NSObject<FridaCalculator>
{
  NSString * name;
}
@end

@implementation FridaDefaultCalculator
- (id)init {
  self = [super init];
  if (self) {
    self->name = @"calc.exe";
  }
  return self;
}
- (int)add:(int)value { return 1337 + value; }
- (void)add:(int)value completion:(void (^)(int, NSError *))block {
  dispatch_async (dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    block (1337 + value, nil);
  });
}
- (void)addSquared:(int)value completion:(void (^)(int, void *))block {
  dispatch_async (dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    block (1337 + (value * value), GSIZE_TO_POINTER (0x42));
  });
}
- (int)sub:(int)value { return 1337 - value; }
- (void)secret {}
@end

TESTCASE (classes_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var numClasses = Object.keys(ObjC.classes).length;"
      "send(numClasses > 100);"
      "var count = 0;"
      "for (var className in ObjC.classes) {"
        "if (ObjC.classes.hasOwnProperty(className)) {"
          "count++;"
        "}"
      "}"
      "send(count === numClasses);"
      "var numClassesNow = Object.keys(ObjC.classes).length;"
      "send(numClassesNow === numClasses);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (protocols_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var numProtocols = Object.keys(ObjC.protocols).length;"
      "send(numProtocols > 100);"
      "var count = 0;"
      "for (var protocolName in ObjC.protocols) {"
        "if (ObjC.protocols.hasOwnProperty(protocolName)) {"
          "count++;"
        "}"
      "}"
      "send(count === numProtocols);"
      "var numProtocolsNow = Object.keys(ObjC.protocols).length;"
      "send(numProtocolsNow === numProtocols);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (object_enumeration_should_contain_parent_methods)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var keys = Object.keys(ObjC.classes.NSDate);"
      "send(keys.indexOf(\"conformsToProtocol_\") !== -1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (object_enumeration_should_contain_protocol_methods)
{
  FridaDefaultCalculator * calc = [[[FridaDefaultCalculator alloc] init]
      autorelease];

  COMPILE_AND_LOAD_SCRIPT (
      "var pool = ObjC.classes.NSAutoreleasePool.alloc().init();"
      "var CalculatorProxy = ObjC.registerProxy({});"
      "var calculatorProxy = new CalculatorProxy(" GUM_PTR_CONST ", {});"
      "var calculator = new ObjC.Object(calculatorProxy, "
          "ObjC.protocols.FridaCalculator);"
      "var keys = Object.keys(calculator);"
      "send(keys.length >= 2);"
      "send(keys.indexOf('add_') !== -1);"
      "send(keys.indexOf('sub_') !== -1);"
      "send(keys.indexOf('magic') === -1);"
      "send(\"magic\" in calculator);"
      "try {"
          "calculator.magic();"
          "send(true);"
      "} catch (e) {"
          "send(false);"
      "}"
      "send(\"secret\" in calculator);"
      "try {"
          "calculator.secret();"
          "send(true);"
      "} catch (e) {"
          "send(false);"
      "}"
      "pool.release();",
      calc);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
}

TESTCASE (class_enumeration_should_not_contain_instance_methods)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var keys = Object.keys(ObjC.classes.NSDate);"
      "send(keys.indexOf(\"dateWithTimeIntervalSinceNow_\") !== -1);"
      "send(keys.indexOf(\"initWithTimeIntervalSinceReferenceDate_\")"
          " !== -1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
}

TESTCASE (instance_enumeration_should_not_contain_class_methods)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var keys = Object.keys(ObjC.classes.NSDate.date());"
      "send(keys.indexOf(\"initWithTimeIntervalSinceReferenceDate_\")"
          " !== -1);"
      "send(keys.indexOf(\"dateWithTimeIntervalSinceNow_\") !== -1);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
}

TESTCASE (class_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSDate = ObjC.classes.NSDate;"
      "send(NSDate instanceof ObjC.Object);"
      "send(\"NSDate\" in ObjC.classes);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (kind_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSDate = ObjC.classes.NSDate;"
      "var now = NSDate.date();"
      "send(now.$kind);"
      "send(NSDate.$kind);"
      "send(NSDate.$class.$kind);");
  EXPECT_SEND_MESSAGE_WITH ("\"instance\"");
  EXPECT_SEND_MESSAGE_WITH ("\"class\"");
  EXPECT_SEND_MESSAGE_WITH ("\"meta-class\"");
}

TESTCASE (super_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(ObjC.classes.NSDate.$super.$className === \"NSObject\");"
      "send(ObjC.classes.NSObject.$super === null);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (class_name_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSDate = ObjC.classes.NSDate;"
      "send(NSDate.$className);"
      "var now = NSDate.date();"
      "send(typeof now.$className);");
  EXPECT_SEND_MESSAGE_WITH ("\"NSDate\"");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
}

TESTCASE (module_name_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSString = ObjC.classes.NSString;"
      "var badger = NSString.stringWithString_(\"badger\");"
      "send(NSString.$moduleName);"
      "send(badger.$moduleName);");
  EXPECT_SEND_MESSAGE_WITH ("\"/System/Library/Frameworks"
      "/Foundation.framework/Versions/C/Foundation\"");
  EXPECT_SEND_MESSAGE_WITH ("\"/System/Library/Frameworks"
      "/CoreFoundation.framework/Versions/A/CoreFoundation\"");
}

TESTCASE (protocols_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSDate = ObjC.classes.NSDate;"
      "send(Object.keys(NSDate.$protocols).length > 0);"
      "var now = NSDate.date();"
      "send(Object.keys(now.$protocols).length >= 0);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (all_method_names_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSDate = ObjC.classes.NSDate;"
      "var methodNames = NSDate.$methods;"
      "send(methodNames.length > 0);"
      "send(typeof methodNames[0]);"
      "send(methodNames.some(function (name) {"
          "return name.indexOf('+ ') === 0;"
      "}));"
      "send(methodNames.some(function (name) {"
          "return name.indexOf('- ') === 0;"
      "}));"
      "var superMethodNames = NSDate.$super.$methods;"
      "send(superMethodNames.length > 0);"
      "send(superMethodNames.length <= methodNames.length);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (own_method_names_can_be_retrieved)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSDate = ObjC.classes.NSDate;"
      "var now = NSDate.date();"
      "var ownMethodNames = now.$ownMethods;"
      "send(ownMethodNames.length > 0);"
      "send(typeof ownMethodNames[0]);"
      "send(ownMethodNames.some(function (name) {"
          "return name.indexOf('+ ') === 0;"
      "}));"
      "send(ownMethodNames.some(function (name) {"
          "return name.indexOf('- ') === 0;"
      "}));"
      "var superMethodNames = now.$super.$ownMethods;"
      "send(superMethodNames.length > 0);"
      "send(ownMethodNames.length != superMethodNames.length);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"string\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (ivars_can_be_accessed)
{
  FridaDefaultCalculator * calc = [[[FridaDefaultCalculator alloc] init]
      autorelease];

  COMPILE_AND_LOAD_SCRIPT (
      "var calc = new ObjC.Object(" GUM_PTR_CONST ");"
      "send(calc.$ivars.name.toString());"
      "calc.$ivars.name = 'Calculator';"
      "send(calc.$ivars.name.toString());"
      "send(Object.keys(calc.$ivars));",
      calc);
  EXPECT_SEND_MESSAGE_WITH ("\"calc.exe\"");
  EXPECT_SEND_MESSAGE_WITH ("\"Calculator\"");
  EXPECT_SEND_MESSAGE_WITH ("[\"isa\",\"name\"]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (class_method_can_be_invoked)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSDate = ObjC.classes.NSDate;"
      "var now = NSDate.date();"
      "send(now instanceof ObjC.Object);");
  EXPECT_SEND_MESSAGE_WITH ("true");
}

TESTCASE (object_can_be_constructed_from_pointer)
{
  NSString * str = [NSString stringWithUTF8String:"Badger"];

  COMPILE_AND_LOAD_SCRIPT (
      "var str = new ObjC.Object(" GUM_PTR_CONST ");"
      "send(str.toString());",
      str);
  EXPECT_SEND_MESSAGE_WITH ("\"Badger\"");
}

TESTCASE (string_can_be_constructed)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSString = ObjC.classes.NSString;"
      "NSString.stringWithUTF8String_(Memory.allocUtf8String(\"Snakes\"));");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (string_can_be_passed_as_argument)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var NSString = ObjC.classes.NSString;"
      "var str = NSString.stringWithUTF8String_(Memory.allocUtf8String(\"Snakes\"));"
      "str = str.stringByAppendingString_(\"Mushrooms\");"
      "send(str.toString());");
  EXPECT_SEND_MESSAGE_WITH ("\"SnakesMushrooms\"");
}

TESTCASE (class_can_be_implemented)
{
  const gchar * class_name = "FridaJSCalculator";

  COMPILE_AND_LOAD_SCRIPT (
      "var FridaJSCalculator = ObjC.registerClass({"
          "name: \"%s\","
          "super: ObjC.classes.NSObject,"
          "protocols: [ObjC.protocols.FridaCalculator],"
          "methods: {"
              "\"- init\": function () {"
                  "var self = this.super.init();"
                  "if (self !== null) {"
                      "ObjC.bind(self, {"
                          "foo: 1234"
                      "});"
                  "}"
                  "return self;"
              "},"
              "\"- dealloc\": function () {"
                  "ObjC.unbind(this.self);"
                  "this.super.dealloc();"
              "},"
              "\"- add:\": function (value) {"
                  "return this.data.foo + value;"
              "},"
              "\"- sub:\": function (value) {"
                  "return this.data.foo - value;"
              "}"
           "}"
      "});"
      "send(FridaJSCalculator.$className === \"%s\");",
      class_name, class_name);
  EXPECT_SEND_MESSAGE_WITH ("true");

  id klass = objc_getClass (class_name);
  g_assert (klass != nil);
  id calculator = [[klass alloc] init];
  g_assert (calculator != nil);
  g_assert_cmpint ([calculator add:6], ==, 1234 + 6);
  g_assert_cmpint ([calculator sub:4], ==, 1234 - 4);
  [calculator release];

  UNLOAD_SCRIPT ();
  g_assert (objc_getClass (class_name) == nil);
}

TESTCASE (block_can_be_implemented)
{
  FridaDefaultCalculator * calc = [[[FridaDefaultCalculator alloc] init]
      autorelease];

  COMPILE_AND_LOAD_SCRIPT (
      "var calc = new ObjC.Object(" GUM_PTR_CONST ");"
      "var onComplete = new ObjC.Block({"
          "retType: 'void',"
          "argTypes: ['int', 'object'],"
          "implementation: function (result, error) {"
              "send([result, error]);"
          "}"
      "});"
      "calc.add_completion_(3, onComplete);",
      calc);
  EXPECT_SEND_MESSAGE_WITH ("[1340,null]");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var calc = new ObjC.Object(" GUM_PTR_CONST ");"
      "var onComplete = new ObjC.Block({"
          "retType: 'void',"
          "argTypes: ['int', 'pointer'],"
          "implementation: function (result, data) {"
              "send([result, data]);"
          "}"
      "});"
      "calc.addSquared_completion_(7, onComplete);",
      calc);
  EXPECT_SEND_MESSAGE_WITH ("[1386,\"0x42\"]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (block_can_be_invoked)
{
  NSString * (^block) (NSString *) = ^NSString * (NSString * name) {
    return [NSString stringWithFormat:@"Hello %@", name];
  };

  COMPILE_AND_LOAD_SCRIPT (
      "var pool = ObjC.classes.NSAutoreleasePool.alloc().init();"
      "var block = new ObjC.Block(" GUM_PTR_CONST ");"
      "send(block instanceof ObjC.Block);"
      "send(block.implementation('Badger').toString());"
      "pool.release();",
      block);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("\"Hello Badger\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (block_can_be_traced_while_invoked)
{
  NSString * (^block) (NSString *) = ^NSString * (NSString * name) {
    return [NSString stringWithFormat:@"Hello %@", name];
  };

  COMPILE_AND_LOAD_SCRIPT (
      "var pool = ObjC.classes.NSAutoreleasePool.alloc().init();"
      "var block = new ObjC.Block(" GUM_PTR_CONST ", {"
          "exceptions: 'propagate',"
          "traps: 'all',"
      "});"

      "Stalker.exclude(Process.getModuleByName('runner'));"
      "Stalker.queueDrainInterval = 0;"

      "Stalker.follow({"
          "events: {"
              "call: true,"
          "},"
          "onCallSummary: function (summary) {"
              "send('onCallSummary');"
          "}"
      "});"

      "send(block.implementation('Badger').toString());"
      "pool.release();"

      "Stalker.flush();",

      block);
  EXPECT_SEND_MESSAGE_WITH ("\"Hello Badger\"");
  EXPECT_SEND_MESSAGE_WITH ("\"onCallSummary\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (block_can_be_migrated_to_the_heap_behind_our_back)
{
  FridaDefaultCalculator * calc = [[[FridaDefaultCalculator alloc] init]
      autorelease];

  COMPILE_AND_LOAD_SCRIPT (
      "var FridaDefaultCalculator = ObjC.classes.FridaDefaultCalculator;"
      "var m = FridaDefaultCalculator['- add:completion:'].implementation;"
      "Interceptor.attach(m, {"
          "onEnter: function (args) {"
              "var originalBlockHandle = args[3];"
              "var block = new ObjC.Block(originalBlockHandle);"
              "var appCallback = block.implementation;"
              "block.implementation = function (result, error) {"
                  "send(this === block);"
                  "send(this.handle.toString() === originalBlockHandle.toString());"
                  "appCallback(result, error);"
                  "send([result, error]);"
              "};"
          "}"
      "});");
  EXPECT_NO_MESSAGES ();

  __block int calls = 0;
  [calc add:3 completion:^void (int result, NSError * error) {
    calls++;
  }];

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("[1340,null]");
  g_assert_cmpint (calls, ==, 1);
}

typedef struct _TestBlock TestBlock;
typedef struct _TestBlockSignature TestBlockSignature;

struct _TestBlock
{
  void * isa;
  int flags;
  int reserved;
  void (* invoke) (TestBlock * block, int value);
  TestBlockSignature * signature;

  int last_seen_value;
};

struct _TestBlockSignature
{
  unsigned long int reserved;
  unsigned long int size;
};

static void test_block_invoke (TestBlock * block, int value);

TESTCASE (block_without_signature_can_be_used_after_calling_declare)
{
  TestBlock block;
  TestBlockSignature block_signature;

  block.isa = _NSConcreteStackBlock;
  block.flags = 0;
  block.reserved = 0;
  block.invoke = test_block_invoke;
  block.signature = &block_signature;
  block.last_seen_value = -1;

  block_signature.reserved = 0;
  block_signature.size = sizeof (TestBlock);

  COMPILE_AND_LOAD_SCRIPT (
      "var block = new ObjC.Block(" GUM_PTR_CONST ");"
      "block.implementation(42);",
      &block);
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: block is missing signature; call declare()");
  g_assert_cmpint (block.last_seen_value, ==, -1);

  COMPILE_AND_LOAD_SCRIPT (
      "var block = new ObjC.Block(" GUM_PTR_CONST ");"
      "send(typeof block.types);"
      "block.declare({ retType: 'void', argTypes: ['int'] });"
      "send(block.types);"
      "block.implementation(42);",
      &block);
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"v12@?0i8\"");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (block.last_seen_value, ==, 42);

  COMPILE_AND_LOAD_SCRIPT (
      "var block = new ObjC.Block(" GUM_PTR_CONST ");"
      "block.declare({ types: 'v12@?0i8' });"
      "send(block.types);"
      "block.implementation(24);",
      &block);
  EXPECT_SEND_MESSAGE_WITH ("\"v12@?0i8\"");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (block.last_seen_value, ==, 24);
}

static void
test_block_invoke (TestBlock * block,
                   int value)
{
  block->last_seen_value = value;
}

TESTCASE (basic_method_implementation_can_be_overridden)
{
  NSString * str = [NSString stringWithUTF8String:"Badger"];

  COMPILE_AND_LOAD_SCRIPT (
      "var NSString = ObjC.classes.NSString;"
      "var method = NSString[\"- description\"];"
      "method.implementation ="
          "ObjC.implement(method, function (handle, selector) {"
              "return NSString.stringWithUTF8String_(Memory.allocUtf8String(\"Snakes\"));"
          "});");
  EXPECT_NO_MESSAGES ();

  NSString * desc = [str description];
  EXPECT_NO_MESSAGES ();

  g_assert_cmpstr (desc.UTF8String, ==, "Snakes");
}

typedef struct _FridaRect FridaRect;
typedef struct _FridaPoint FridaPoint;
typedef struct _FridaSize FridaSize;
typedef union _FridaUnion FridaUnion;

struct _FridaPoint
{
  double x;
  double y;
};

struct _FridaSize
{
  double width;
  double height;
};

struct _FridaRect
{
  FridaPoint origin;
  FridaSize size;
};

union _FridaUnion
{
  unsigned short s;
  unsigned int i;
  unsigned long long l;
};

@interface FridaWidget : NSObject
@end

@implementation FridaWidget

- (FridaPoint)position {
  FridaPoint p;
  p.x = 10.0;
  p.y = 15.0;
  return p;
}

- (FridaRect)bounds {
  FridaRect r;
  r.origin.x = 10.0;
  r.origin.y = 15.0;
  r.size.width = 30.0;
  r.size.height = 35.0;
  return r;
}

- (float)width {
  return 30.0f;
}

- (double)height {
  return 35.0f;
}

- (int)drawRect:(FridaRect)dirtyRect {
  return (int) dirtyRect.origin.x + (int) dirtyRect.origin.y +
      (int) dirtyRect.size.width + (int) dirtyRect.size.height;
}

@end

TESTCASE (struct_consuming_method_implementation_can_be_overridden)
{
  FridaWidget * widget = [[[FridaWidget alloc] init] autorelease];
  FridaRect r;

  COMPILE_AND_LOAD_SCRIPT (
      "var FridaWidget = ObjC.classes.FridaWidget;"
      "var method = FridaWidget[\"- drawRect:\"];"
      "var oldImpl = method.implementation;"
      "method.implementation ="
          "ObjC.implement(method, function (handle, selector, dirtyRect) {"
              "send(dirtyRect);"
              "var result = oldImpl(handle, selector, dirtyRect);"
              "return result;"
          "});");
  EXPECT_NO_MESSAGES ();

  r.origin.x = 10.0;
  r.origin.y = 15.0;
  r.size.width = 30.0;
  r.size.height = 35.0;
  int result = [widget drawRect:r];
  EXPECT_SEND_MESSAGE_WITH ("[[10,15],[30,35]]");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (result, ==, 90);
}

TESTCASE (struct_returning_method_can_be_called)
{
  FridaWidget * widget = [[[FridaWidget alloc] init] autorelease];

  COMPILE_AND_LOAD_SCRIPT (
      "var widget = new ObjC.Object(" GUM_PTR_CONST ");"
      "send(widget.position());",
      widget);
  EXPECT_SEND_MESSAGE_WITH ("[10,15]");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "var widget = new ObjC.Object(" GUM_PTR_CONST ");"
      "send(widget.bounds());",
      widget);
  EXPECT_SEND_MESSAGE_WITH ("[[10,15],[30,35]]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (floating_point_returning_method_can_be_called)
{
  FridaWidget * widget = [[[FridaWidget alloc] init] autorelease];

  COMPILE_AND_LOAD_SCRIPT (
      "var widget = new ObjC.Object(" GUM_PTR_CONST ");"
      "send([widget.width(), widget.height()]);",
      widget);
  EXPECT_SEND_MESSAGE_WITH ("[30,35]");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (attempt_to_read_inexistent_property_should_yield_undefined)
{
  COMPILE_AND_LOAD_SCRIPT (
      "send(typeof ObjC.classes.NSDate.snakesAndMushrooms);");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
}

TESTCASE (proxied_method_can_be_invoked)
{
  FridaDefaultCalculator * calc = [[[FridaDefaultCalculator alloc] init]
      autorelease];

  COMPILE_AND_LOAD_SCRIPT (
      "var pool = ObjC.classes.NSAutoreleasePool.alloc().init();"
      "var CalculatorProxy = ObjC.registerProxy({});"
      "var calculatorProxy = new CalculatorProxy(" GUM_PTR_CONST ", {});"
      "var calculator = new ObjC.Object(calculatorProxy);"
      "send(\"- add:\" in calculator);"
      "send(calculator.add_(3));"
      "pool.release();",
      calc);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("1340");
}

TESTCASE (proxied_method_can_be_overridden)
{
  FridaDefaultCalculator * calc = [[[FridaDefaultCalculator alloc] init]
      autorelease];

  COMPILE_AND_LOAD_SCRIPT (
      "var pool = ObjC.classes.NSAutoreleasePool.alloc().init();"
      "var CalculatorProxy = ObjC.registerProxy({});"
      "var calculatorProxy = new CalculatorProxy(" GUM_PTR_CONST ", {});"
      "var calculator = new ObjC.Object(calculatorProxy);"
      "var method = calculator.add_;"
      "method.implementation ="
          "ObjC.implement(method, function (handle, selector, value) {"
              "return 1227 + value;"
          "});"
      "pool.release();"
      "send('ready');",
      calc);
  EXPECT_SEND_MESSAGE_WITH ("\"ready\"");

  g_assert_cmpint ([calc add:3], ==, 1230);
}

@interface FridaTest1 : NSObject
+ (int)foo_;
+ (int)fooBar_;
+ (int)fooBar:(int)a;
+ (int):(int)a;
+ (int):(int)a :(int)b;
@end

@implementation FridaTest1
+ (int)foo_ {
  return 1;
}
+ (int)fooBar_ {
  return 2;
}
+ (int)fooBar:(int)a {
  return 3;
}
+ (int):(int)a {
  return 4;
}
+ (int):(int)a :(int)b {
  return 5;
}
@end

TESTCASE (methods_with_weird_names_can_be_invoked)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var FridaTest1 = ObjC.classes.FridaTest1;"
      "var methodNames = ['foo_', 'fooBar_', 'fooBar:', ':', '::'];"
      "var args = [0, 0, 1, 1, 2];"
      "for (var i = 0; i < methodNames.length; i++) {"
          "var m = FridaTest1['+ ' + methodNames[i]];"
          "var val = m.apply(FridaTest1, args[i] == 0? []: args[i] == 1? [0]: [0, 0]);"
          "send(val == i + 1);"
      "}");

  for (gint i = 0; i != 5; i++)
  {
    EXPECT_SEND_MESSAGE_WITH ("true");
  }
}

@interface FridaTest2 : NSObject
@end

#define METHOD(t, n) + (t)_ ## n:(t)x { return x; }
@implementation FridaTest2
METHOD(char, char)
METHOD(int, int)
METHOD(short, short)
METHOD(long, long)
METHOD(long long, long_long)
METHOD(unsigned char, unsigned_char)
METHOD(unsigned int, unsigned_int)
METHOD(unsigned short, unsigned_short)
METHOD(unsigned long, unsigned_long)
METHOD(unsigned long long, unsigned_long_long)
METHOD(float, float)
METHOD(double, double)
METHOD(_Bool, _Bool)
METHOD(char *, char_ptr)
METHOD(id, id)
METHOD(Class, Class)
METHOD(SEL, SEL)
METHOD(FridaUnion, FridaUnion)
@end

TESTCASE (method_call_preserves_value)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var FridaTest2 = ObjC.classes.FridaTest2;"
      "function test(method, value) {"
          "var arg_value = value;"
          "if (typeof value === 'string') {"
              "arg_value = Memory.allocUtf8String(value);"
          "}"
          "var result = FridaTest2['+ _' + method + ':'](arg_value);"
          "var same = result === value;"
          "if (typeof result === 'number') {"
              "if (isNaN(result)) {"
                  "same = isNaN(value);"
              "}"
          "} else if (typeof result === 'object') {"
              "if (result instanceof Int64) {"
                  "same = result.toNumber() === value;"
              "} else if (result instanceof UInt64) {"
                  "same = result.toNumber() === value;"
              "} else if (result instanceof NativePointer) {"
                  "same = value instanceof NativePointer &&"
                      "result.toString() === value.toString();"
              "} else if (result instanceof ObjC.Object) {"
                  "same = result.handle.toString() === value.handle.toString();"
              "}"
          "}"
          "send(same);"
      "}"
      "test('char', 127);"
      "test('char', -128);"
      "test('int', -467);"
      "test('int', 150);"
      "test('short', -56);"
      "test('short', 562);"
      "test('long',  0x7fffffff);"
      "test('long', -0x80000000);"
      "test('long_long', 0x7fffffff);"
      "test('long_long', -0x80000000);"
      "test('unsigned_char', 0);"
      "test('unsigned_char', 255);"
      "test('unsigned_int', Math.pow(2, 16) - 1);"
      "test('unsigned_int', 0x1234);"
      "test('unsigned_short', 0xffff);"
      "test('unsigned_long', 0xffffffff);"
      "test('unsigned_long_long', Math.pow(2, 63));"
      "test('float', 1.5);"
      "test('float', -5.75);"
      "test('float', -0.0);"
      "test('float', Infinity);"
      "test('float', -Infinity);"
      "test('float', NaN);"
      "test('double', Math.pow(10, 300));"
      "test('double', -Math.pow(10, 300));"
      "test('double', -0.0);"
      "test('double', Infinity);"
      "test('double', -Infinity);"
      "test('double', NaN);"
      "test('_Bool', false);"
      "test('_Bool', true);"
      "test('char_ptr', 'foobar');"
      "test('char_ptr', 'frida');"
      "test('id', FridaTest2);"
      "test('id', ObjC.classes.NSObject.new());"
      "test('Class', FridaTest2);"
      "test('Class', ObjC.classes.NSObject);"
      "test('SEL', ObjC.selector('foo'));"
      "test('SEL', ObjC.selector('foo:bar:baz:'));"
      "test('FridaUnion', 12345);");

  for (gint i = 0; i != 40; i++)
  {
    EXPECT_SEND_MESSAGE_WITH ("true");
  }
}

TESTCASE (method_call_can_be_traced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var FridaTest1 = ObjC.classes.FridaTest1;"
      "var fooBar = FridaTest1.fooBar_.clone({"
          "exceptions: 'propagate',"
          "traps: 'all',"
      "});"

      "Stalker.exclude(Process.getModuleByName('runner'));"
      "Stalker.queueDrainInterval = 0;"

      "Stalker.follow({"
          "events: {"
              "call: true,"
          "},"
          "onCallSummary: function (summary) {"
              "send('onCallSummary');"
          "}"
      "});"

      "fooBar.call(FridaTest1, 42);"

      "Stalker.flush();");
  EXPECT_SEND_MESSAGE_WITH ("\"onCallSummary\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (objects_can_be_serialized_to_json)
{
  COMPILE_AND_LOAD_SCRIPT (
      "JSON.parse(JSON.stringify(ObjC));"
      "JSON.parse(JSON.stringify(ObjC.classes.NSObject));");
  EXPECT_NO_MESSAGES ();
}

@interface FridaTest3 : NSObject
@end
@implementation FridaTest3
@end

@interface FridaTest4 : FridaTest3
@end
@implementation FridaTest4
@end

TESTCASE (classes_can_be_enumerated_without_filtering)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var classes = ObjC.enumerateLoadedClassesSync();"
      "var owners = Object.keys(classes);"
      "send(owners.length > 1);"
      "var runnerPath = Process.enumerateModulesSync()[0].path;"
      "send(classes[runnerPath] !== undefined);"
      "send(classes[runnerPath].indexOf('FridaTest3') !== -1)");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (classes_can_be_enumerated_with_filtering)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var runnerPath = Process.enumerateModulesSync()[0].path;"
      "var runnerModules = new ModuleMap(isRunnerModule);"
      "function isRunnerModule(m) {"
          "return m.path === runnerPath;"
      "}"
      "var classes = ObjC.enumerateLoadedClassesSync({"
          "ownedBy: runnerModules"
      "});"
      "var owners = Object.keys(classes);"
      "send(owners.length === 1);"
      "send(owners[0] === runnerPath);");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (swift_classes_can_be_enumerated)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var classes = ObjC.enumerateLoadedClassesSync();"
      "var runnerPath = Process.enumerateModulesSync()[0].path;"
      "send(classes[runnerPath].indexOf('FridaObjCTests.Taylor') !== -1)");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (existing_instances_can_be_discovered)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "function testChoose(obj, cls, noSubclasses) {"
          "return ObjC.chooseSync({class: cls, subclasses: !noSubclasses}).filter(x => x.handle.equals(obj.handle)).length === 1;"
      "}"
      "var FridaTest3 = ObjC.classes.FridaTest3;"
      "var FridaTest4 = ObjC.classes.FridaTest4;"
      "var obj3 = FridaTest3.new();"
      "var obj4 = FridaTest4.new();"
      "send(testChoose(obj3, FridaTest3));"
      "send(!testChoose(obj3, FridaTest4));"
      "send(testChoose(obj4, FridaTest3));"
      "send(testChoose(obj4, FridaTest4));"
      "send(testChoose(obj3, FridaTest3, true));"
      "send(!testChoose(obj3, FridaTest4, true));"
      "send(!testChoose(obj4, FridaTest3, true));"
      "send(testChoose(obj4, FridaTest4, true));");

  for (gint i = 0; i != 8; i++)
  {
    EXPECT_SEND_MESSAGE_WITH ("true");
  }
}

TESTCASE (function_can_be_scheduled_on_a_dispatch_queue)
{
  COMPILE_AND_LOAD_SCRIPT (
      "var fridaThreadId = Process.getCurrentThreadId();"
      "ObjC.schedule(" GUM_PTR_CONST ", function () {"
          "send(Process.getCurrentThreadId() !== fridaThreadId);"
      "});", dispatch_get_global_queue (DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
  UNLOAD_SCRIPT ();
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (performance)
{
  TestMessageItem * item;
  gint duration;

  COMPILE_AND_LOAD_SCRIPT (
      "ObjC.classes.NSObject;"
      "var start = Date.now();"
      "Object.keys(ObjC.classes.NSDictionary);"
      "var end = Date.now();"
      "send(end - start);");
  item = test_fixture_pop_message (fixture);
  sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &duration);
  g_print ("<%d ms> ", duration);
  test_message_item_free (item);
}
