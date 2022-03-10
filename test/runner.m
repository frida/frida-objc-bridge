#include "fixture.h"

#include <frida-gumjs.h>

#define RUN_SUITE(name)                                             \
  TEST_RUN_LIST_WITH_DATA (name, gum_script_backend_obtain_qjs ()); \
  if (v8_backend != NULL)                                           \
    TEST_RUN_LIST_WITH_DATA (name, v8_backend)

static gchar * load_bundle (void);

static gchar * detect_runner_location (void);
static gboolean store_path_of_test_runner (const GumModuleDetails * details,
    gpointer user_data);

gchar * frida_objc_bundle = NULL;
guint num_tests_run = 0;

int
main (int argc, char * argv[])
{
  gint result;
  GumExceptor * exceptor;
  GumScriptBackend * v8_backend = NULL;
  gdouble t;

  gum_init_embedded ();
  g_test_init (&argc, &argv, NULL);

#ifdef HAVE_IOS
  if (g_file_test ("/usr/lib/libjailbreak.dylib", G_FILE_TEST_EXISTS))
  {
    GModule * module;
    void (* entitle_now) (pid_t pid);

    module = g_module_open ("/usr/lib/libjailbreak.dylib", G_MODULE_BIND_LAZY);

    entitle_now = NULL;
    g_module_symbol (module, "jb_oneshot_entitle_now",
        (gpointer *) &entitle_now);

    entitle_now (getpid ());

    g_module_close (module);
  }
#endif

  frida_objc_bundle = load_bundle ();

  exceptor = gum_exceptor_obtain ();

#ifdef HAVE_V8
  v8_backend = gum_script_backend_obtain_v8 ();
#endif

  RUN_SUITE (basics);

  @autoreleasepool
  {
    GTimer * timer = g_timer_new ();

    result = g_test_run ();

    t = g_timer_elapsed (timer, NULL);
    g_timer_destroy (timer);
  }

  g_print ("\nRan %d test%s in %.2f seconds\n",
      num_tests_run,
      (num_tests_run != 1) ? "s" : "",
      t);

  g_clear_object (&exceptor);

  return result;
}

static gchar *
load_bundle (void)
{
  gchar * bundle_source;
  gchar * runner_location, * runner_dir;
  gchar * bundle_dir, * bundle_location;
  GError * error;

  runner_location = detect_runner_location ();
  runner_dir = g_path_get_dirname (runner_location);
#ifdef HAVE_MACOS
  bundle_dir = g_path_get_dirname (runner_dir);
#else
  bundle_dir = g_strdup (runner_dir);
#endif
  bundle_location = g_build_filename (bundle_dir, "frida-objc-bridge.js", NULL);
  g_free (bundle_dir);
  g_free (runner_dir);
  g_free (runner_location);

  if (!g_file_get_contents (bundle_location, &bundle_source, NULL, &error))
  {
    g_printerr ("Unable to load bundle: %s\n", error->message);
    exit (1);
  }

  return bundle_source;
}

static gchar *
detect_runner_location (void)
{
  gchar * location = NULL;

  gum_process_enumerate_modules (store_path_of_test_runner, &location);
  g_assert (location != NULL);

  return location;
}

static gboolean
store_path_of_test_runner (const GumModuleDetails * details,
                           gpointer user_data)
{
  gchar ** path = user_data;

  *path = g_strdup (details->path);

  return FALSE;
}
