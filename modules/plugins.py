#!/usr/bin/env python3
# plugins.py — Plugin system (JagoX v1.0.0)
# Part of JagoX framework — MIT License
#
# Plugin auto-load dari modules/plugins/*.py
# Setiap plugin bisa implement 1 atau lebih event handler:
#   on_start(context)              — dipanggil di awal pipeline
#   on_target(target_info)         — tiap target sebelum scan
#   on_host_result(host_data)      — tiap host setelah nmap
#   on_finding(finding_dict)       — tiap finding
#   on_end(summary)                — di akhir pipeline
#
# Public API (kompatibel nmpx.py v1.0.0):
#   load_plugins(plugin_dir=None) -> PluginManager
#   manager.fire(event, data)
#   manager.list_plugins()

import os
import sys
import importlib.util
import traceback

__version__ = "1.0.0"

# Event yang didukung
EVENTS = ["start", "target", "host_result", "finding", "end"]


class PluginManager:
    """Manager untuk load dan fire plugin events."""

    def __init__(self, plugin_dir=None):
        # Default: <root>/plugins/ (sibling dari modules/)
        _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.plugin_dir = plugin_dir or os.path.join(_root, "plugins")
        self.plugins = []  # list of (name, module, handlers)

    def load_all(self):
        """Auto-discover .py di plugin_dir."""
        if not os.path.isdir(self.plugin_dir):
            return
        for fname in sorted(os.listdir(self.plugin_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            self._load_one(os.path.join(self.plugin_dir, fname))

    def _load_one(self, path):
        """Load satu plugin, return True kalau punya handler."""
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            spec = importlib.util.spec_from_file_location(
                f"jagox_plugin_{name}", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            handlers = {}
            for ev in EVENTS:
                h = getattr(mod, f"on_{ev}", None)
                if callable(h):
                    handlers[ev] = h
            if handlers:
                self.plugins.append((name, mod, handlers))
                return True
            return False
        except Exception as e:
            try:
                print(f"[plugin] ⚠ Gagal load '{name}': {e}",
                       file=sys.stderr)
            except Exception:
                pass
            return False

    def fire(self, event, data=None):
        """Panggil semua handler untuk event. Try/except per plugin."""
        for name, mod, handlers in self.plugins:
            h = handlers.get(event)
            if not h:
                continue
            try:
                h(data)
            except Exception as e:
                try:
                    print(f"[plugin] ⚠ '{name}.on_{event}' error: {e}",
                           file=sys.stderr)
                except Exception:
                    pass

    def list_plugins(self):
        return [{"name": n, "handlers": list(h.keys()),
                  "path": getattr(m, "__file__", "?")}
                for n, m, h in self.plugins]

    def __len__(self):
        return len(self.plugins)


def load_plugins(plugin_dir=None):
    """Helper: load semua plugin, return manager."""
    m = PluginManager(plugin_dir)
    m.load_all()
    return m


# ============================================================
# CLI — list plugin
# ============================================================
def _cli():
    import argparse
    import os

    try:
        from . import banner as _bn
    except ImportError:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import banner as _bn
        except ImportError:
            _bn = None
    if _bn is not None:
        try:
            from rich.console import Console
            _bn.print_banner(console=Console(), version=__version__,
                              subtitle="Plugin System — JagoX")
        except ImportError:
            _bn.print_banner()

    parser = argparse.ArgumentParser(
        description="JagoX plugins — manage plugin system")
    parser.add_argument("--dir", help="Custom plugin directory")
    parser.add_argument("--version", action="version",
                        version=f"JagoX plugins v{__version__}")
    args = parser.parse_args()

    m = load_plugins(args.dir)
    print(f"\nPlugin directory: {m.plugin_dir}")
    print(f"Plugin ter-load : {len(m)}")

    if not m.plugins:
        print("\n[!] Tidak ada plugin. Buat file .py di:")
        print(f"    {m.plugin_dir}/")
        print("\nContoh plugin minimal:")
        print("  # modules/plugins/myplugin.py")
        print("  def on_finding(f):")
        print("      if f.get('risk') == 'CRITICAL':")
        print("          print(f'[!] {f.get(\"host\")}')")
        return

    print()
    for p in m.list_plugins():
        print(f"  ✔ {p['name']:<20} handlers: {', '.join(p['handlers'])}")


if __name__ == "__main__":
    _cli()
