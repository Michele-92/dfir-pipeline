#!/usr/bin/env python3
import subprocess
import threading
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

# Pre-load pipeline modules while GUI renders
def _preload():
    try:
        from models.pipeline_context import PipelineContext
        from stages import (
            stage01_detection, stage02_memory, stage03_profiling,
            stage04_disk, stage04_1_autopsy, stage05_tsk, stage06_logs,
            stage07_ioc, stage08_normalize, stage09_antiforensics,
            stage10_ml, stage11_mitre, stage12_aggregation,
            stage13_quality, stage14_export,
        )
    except Exception:
        pass

threading.Thread(target=_preload, daemon=True).start()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PIPELINE_DIR = Path(__file__).parent


class DFIRApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DFIR Pipeline")
        self.geometry("620x620")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(
            self, text="DFIR Pipeline",
            font=ctk.CTkFont(size=30, weight="bold")
        ).pack(pady=(32, 4))

        ctk.CTkLabel(
            self, text="Forensische Analyse-Pipeline",
            font=ctk.CTkFont(size=13),
            text_color="gray"
        ).pack(pady=(0, 24))

        # ── Haupteinstellungen ─────────────────────────────────────────────
        main = ctk.CTkFrame(self, corner_radius=14)
        main.pack(padx=32, fill="x")

        # Disk-Image
        ctk.CTkLabel(main, text="Disk-Image", font=ctk.CTkFont(weight="bold"), anchor="w").pack(
            padx=20, pady=(20, 4), fill="x"
        )
        r1 = ctk.CTkFrame(main, fg_color="transparent")
        r1.pack(padx=20, fill="x", pady=(0, 14))
        self.image_var = ctk.StringVar()
        ctk.CTkEntry(r1, textvariable=self.image_var, placeholder_text="/pfad/zum/image.E01").pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        ctk.CTkButton(r1, text="Auswählen", width=110, command=self._pick_image).pack(side="right")

        # Output-Verzeichnis
        ctk.CTkLabel(main, text="Output-Verzeichnis", font=ctk.CTkFont(weight="bold"), anchor="w").pack(
            padx=20, pady=(0, 4), fill="x"
        )
        r2 = ctk.CTkFrame(main, fg_color="transparent")
        r2.pack(padx=20, fill="x", pady=(0, 14))
        self.output_var = ctk.StringVar(value=str(PIPELINE_DIR / "output"))
        ctk.CTkEntry(r2, textvariable=self.output_var).pack(
            side="left", fill="x", expand=True, padx=(0, 8)
        )
        ctk.CTkButton(r2, text="Auswählen", width=110, command=self._pick_output).pack(side="right")

        # Worker-Slider
        ctk.CTkLabel(main, text="Worker", font=ctk.CTkFont(weight="bold"), anchor="w").pack(
            padx=20, pady=(0, 4), fill="x"
        )
        r3 = ctk.CTkFrame(main, fg_color="transparent")
        r3.pack(padx=20, fill="x", pady=(0, 20))
        self.workers_var = ctk.IntVar(value=2)
        self._workers_label = ctk.CTkLabel(r3, text="2", width=24)
        self._workers_label.pack(side="right")
        ctk.CTkSlider(
            r3, from_=1, to=8, number_of_steps=7,
            variable=self.workers_var,
            command=lambda v: self._workers_label.configure(text=str(int(float(v))))
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        # ── Optionen ───────────────────────────────────────────────────────
        opts = ctk.CTkFrame(self, corner_radius=14)
        opts.pack(padx=32, fill="x", pady=(12, 0))
        ctk.CTkLabel(opts, text="Optionen", font=ctk.CTkFont(weight="bold"), anchor="w").pack(
            padx=20, pady=(14, 8), fill="x"
        )
        r4 = ctk.CTkFrame(opts, fg_color="transparent")
        r4.pack(padx=20, fill="x", pady=(0, 14))
        self.no_autopsy_var = ctk.BooleanVar()
        self.no_timesketch_var = ctk.BooleanVar()
        ctk.CTkCheckBox(r4, text="Autopsy deaktivieren", variable=self.no_autopsy_var).pack(
            side="left", padx=(0, 24)
        )
        ctk.CTkCheckBox(r4, text="Timesketch deaktivieren", variable=self.no_timesketch_var).pack(
            side="left"
        )

        # ── Start-Button ───────────────────────────────────────────────────
        self._start_btn = ctk.CTkButton(
            self, text="Start", height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self._start
        )
        self._start_btn.pack(padx=32, pady=20, fill="x")

        self._status = ctk.CTkLabel(self, text="Bereit", text_color="gray", font=ctk.CTkFont(size=12))
        self._status.pack()

    # ── Hilfsmethoden ──────────────────────────────────────────────────────

    def _pick_image(self):
        path = filedialog.askopenfilename(
            title="Disk-Image auswählen",
            filetypes=[
                ("Disk Images", "*.E01 *.dd *.vmdk *.raw *.img"),
                ("Alle Dateien", "*.*"),
            ],
        )
        if path:
            self.image_var.set(path)

    def _pick_output(self):
        path = filedialog.askdirectory(title="Output-Verzeichnis auswählen")
        if path:
            self.output_var.set(path)

    def _build_command(self):
        image   = self.image_var.get().strip()
        output  = self.output_var.get().strip()
        workers = int(self.workers_var.get())

        cmd = f'python pipeline.py "{image}" --output_dir "{output}" --workers {workers}'
        if self.no_autopsy_var.get():
            cmd += " --no-autopsy"
        if self.no_timesketch_var.get():
            cmd += " --no-timesketch"
        return cmd

    def _start(self):
        if not self.image_var.get().strip():
            self._status.configure(text="Bitte ein Disk-Image auswählen", text_color="orange")
            return

        cmd = self._build_command()
        self._status.configure(text="Pipeline gestartet", text_color="#4CAF50")

        subprocess.Popen(
            f'cmd /k "{cmd}"',
            shell=True,
            cwd=str(PIPELINE_DIR),
        )


if __name__ == "__main__":
    app = DFIRApp()
    app.mainloop()
