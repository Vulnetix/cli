import shutil


def install_plugin(saved_path, plugin_dir):
~>    shutil.unpack_archive(saved_path, plugin_dir)
    register(plugin_dir)
