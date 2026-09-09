#!/usr/bin/env python3
"""
Wrapper que mide el tiempo entre cada input del teclado.
Funciona en Windows y Linux sin modificar el codigo del proyecto.
"""
import time
import sys
import os

# Asegurar que el directorio del proyecto esta en el path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TimedStdscr:
    """Proxy que envuelve el stdscr real y registra los tiempos de cada getch()."""

    def __init__(self, real_stdscr):
        # Usar object.__setattr__ para evitar recursion infinita
        object.__setattr__(self, "_real", real_stdscr)
        object.__setattr__(self, "_timestamps", [])

    def getch(self):
        t0 = time.perf_counter()
        result = self._real.getch()
        t1 = time.perf_counter()
        self._timestamps.append((t0, t1, result))
        return result

    # Delegar todo lo demas al stdscr real
    def __getattr__(self, name):
        return getattr(self._real, name)


# Hookar app.run para inyectar nuestro proxy
_original_run = None
_captured_app = None


def run_with_timing():
    global _original_run, _captured_app

    from design.Menu import MenuApp

    _original_run = MenuApp.run

    def patched_run(self, stdscr):
        timed = TimedStdscr(stdscr)
        # Guardar referencia para el reporte final
        global _captured_app
        _captured_app = self
        # Llamar al run original con nuestro proxy
        return _original_run(self, timed)

    MenuApp.run = patched_run

    # Ejecutar la app
    from App import main
    main()

    # ---- Reporte al salir ----
    # Recuperar los timestamps del proxy
    # Buscar el timed_stdscr que creamos
    print("\n" + "=" * 60)
    print("  INPUT TIMING REPORT")
    print("=" * 60)

    # Los timestamps estan en el ultimo patched_run que se ejecuto
    # Los guardamos en una variable global
    ts = _get_timestamps()
    if not ts:
        print("No input timestamps captured.")
        print("=" * 60)
        return

    print(f"  Total keypresses: {len(ts)}")

    if len(ts) > 1:
        # Tiempo entre teclas (reaccion del usuario)
        intervals = []
        for i in range(1, len(ts)):
            dt = ts[i][0] - ts[i - 1][1]
            intervals.append(dt * 1000)  # a milisegundos

        print(f"  Avg time between keys:  {sum(intervals) / len(intervals):.1f}ms")
        print(f"  Max time between keys:  {max(intervals):.1f}ms")
        print(f"  Min time between keys:  {min(intervals):.1f}ms")
        print(f"  Total session time:     {sum(intervals) / 1000:.2f}s")

        # Tiempo de procesamiento (lo que tarda la app en responder)
        proc_times = [(t1 - t0) * 1000 for t0, t1, _ in ts]
        print(f"\n  Avg processing per key: {sum(proc_times) / len(proc_times):.1f}ms")
        print(f"  Max processing per key: {max(proc_times):.1f}ms")

        # Top 5 teclas mas lentas
        slow = sorted(zip(proc_times, ts), key=lambda x: -x[0])[:5]
        print("\n  Slowest keys:")
        for ms, (t0, t1, key) in slow:
            if key == -1:
                keyname = "timeout (no key)"
            elif key == 10 or key == 13:
                keyname = "Enter"
            elif key == 27:
                keyname = "Esc"
            elif key == 258:
                keyname = "Down"
            elif key == 259:
                keyname = "Up"
            elif key == 260:
                keyname = "Left"
            elif key == 261:
                keyname = "Right"
            elif key == 338:
                keyname = "PgDn"
            elif key == 339:
                keyname = "PgUp"
            elif 32 <= key < 127:
                keyname = f"'{chr(key)}'"
            else:
                keyname = f"key={key}"
            print(f"    {ms:8.1f}ms  {keyname}")

    print("=" * 60)


# Variable global para guardar los timestamps del proxy
_global_timestamps = []


def _get_timestamps():
    return _global_timestamps


def patched_run_factory():
    """Crea un run parchado que guarda timestamps globalmente."""
    from design.Menu import MenuApp

    original_run = MenuApp.run

    def patched_run(self, stdscr):
        proxy = TimedStdscr(stdscr)
        # Conectar el proxy para que sus timestamps sean accesibles
        original_addch = proxy._real.addstr

        # Guardar timestamps en global
        def timed_getch():
            t0 = time.perf_counter()
            result = proxy._real.getch()
            t1 = time.perf_counter()
            _global_timestamps.append((t0, t1, result))
            return result

        # Reemplazar getch del proxy
        object.__setattr__(proxy, "getch", timed_getch)

        return original_run(self, proxy)

    MenuApp.run = patched_run


if __name__ == "__main__":
    patched_run_factory()

    try:
        from App import main
        main()
    except KeyboardInterrupt:
        pass

    # ---- Reporte ----
    ts = _global_timestamps

    print("\n" + "=" * 60)
    print("  INPUT TIMING REPORT")
    print("=" * 60)

    if not ts:
        print("  No input timestamps captured.")
        print("=" * 60)
        sys.exit(0)

    print(f"  Total keypresses: {len(ts)}")

    if len(ts) > 1:
        intervals = []
        for i in range(1, len(ts)):
            dt = ts[i][0] - ts[i - 1][1]
            intervals.append(dt * 1000)

        print(f"  Avg time between keys:  {sum(intervals) / len(intervals):.1f}ms")
        print(f"  Max time between keys:  {max(intervals):.1f}ms")
        print(f"  Min time between keys:  {min(intervals):.1f}ms")
        print(f"  Total session time:     {sum(intervals) / 1000:.2f}s")

        proc_times = [(t1 - t0) * 1000 for t0, t1, _ in ts]
        print(f"\n  Avg processing per key: {sum(proc_times) / len(proc_times):.1f}ms")
        print(f"  Max processing per key: {max(proc_times):.1f}ms")

        slow = sorted(zip(proc_times, ts), key=lambda x: -x[0])[:5]
        print("\n  Slowest keys:")
        for ms, (t0, t1, key) in slow:
            if key == -1:
                keyname = "timeout (no key)"
            elif key in (10, 13):
                keyname = "Enter"
            elif key == 27:
                keyname = "Esc"
            elif key == 258:
                keyname = "Down"
            elif key == 259:
                keyname = "Up"
            elif key == 260:
                keyname = "Left"
            elif key == 261:
                keyname = "Right"
            elif key == 338:
                keyname = "PgDn"
            elif key == 339:
                keyname = "PgUp"
            elif 32 <= key < 127:
                keyname = f"'{chr(key)}'"
            else:
                keyname = f"key={key}"
            print(f"    {ms:8.1f}ms  {keyname}")

    print("=" * 60)
