// SecureShare — small, dependency-free UI behaviors.
// Nothing here touches cryptography; all encryption happens server-side.
// This file only handles: drag & drop, upload progress, the notification
// panel, the mobile sidebar toggle, and "copy to clipboard" buttons.

document.addEventListener("DOMContentLoaded", function () {
    initFlashAutoDismiss();
    initSidebarToggle();
    initNotifPanel();
    initCopyButtons();
    initUploadDropzone();
    initConfirmForms();
});

function initFlashAutoDismiss() {
    document.querySelectorAll(".flash").forEach(function (el, i) {
        setTimeout(function () {
            el.style.transition = "opacity 0.25s ease, transform 0.25s ease";
            el.style.opacity = "0";
            el.style.transform = "translateX(12px)";
            setTimeout(function () { el.remove(); }, 260);
        }, 5000 + i * 400);
    });
}

function initSidebarToggle() {
    var btn = document.getElementById("sidebarToggle");
    var sidebar = document.querySelector(".sidebar");
    if (!btn || !sidebar) return;
    btn.addEventListener("click", function () {
        sidebar.classList.toggle("open");
    });
    document.addEventListener("click", function (e) {
        if (sidebar.classList.contains("open") && !sidebar.contains(e.target) && e.target !== btn) {
            sidebar.classList.remove("open");
        }
    });
}

function initNotifPanel() {
    var toggle = document.getElementById("notifToggle");
    var panel = document.getElementById("notifPanel");
    if (!toggle || !panel) return;

    toggle.addEventListener("click", function (e) {
        e.stopPropagation();
        panel.classList.toggle("open");
    });

    document.addEventListener("click", function (e) {
        if (!panel.contains(e.target) && e.target !== toggle) {
            panel.classList.remove("open");
        }
    });

    var markReadForm = document.getElementById("markReadForm");
    if (markReadForm && toggle.dataset.unread === "true") {
        toggle.addEventListener("click", function () {
            fetch(markReadForm.action, {
                method: "POST",
                headers: {
                    "X-Requested-With": "XMLHttpRequest",
                    "X-CSRFToken": markReadForm.querySelector('[name="csrf_token"]').value,
                },
            }).then(function () {
                var dot = toggle.querySelector(".dot");
                if (dot) dot.remove();
                toggle.dataset.unread = "false";
            }).catch(function () {});
        }, { once: true });
    }
}

function initCopyButtons() {
    document.querySelectorAll("[data-copy-target]").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var target = document.querySelector(btn.getAttribute("data-copy-target"));
            if (!target) return;
            var text = target.value !== undefined ? target.value : target.textContent;
            navigator.clipboard.writeText(text).then(function () {
                var original = btn.textContent;
                btn.textContent = "Copied!";
                setTimeout(function () { btn.textContent = original; }, 1500);
            }).catch(function () {
                target.select && target.select();
            });
        });
    });
}

function initConfirmForms() {
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
        form.addEventListener("submit", function (e) {
            if (!confirm(form.getAttribute("data-confirm"))) {
                e.preventDefault();
            }
        });
    });
}

function humanFileSize(bytes) {
    var units = ["B", "KB", "MB", "GB"];
    var i = 0;
    while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
    return (i === 0 ? bytes : bytes.toFixed(1)) + " " + units[i];
}

function fileIconGlyph(name) {
    var ext = (name.split(".").pop() || "").toLowerCase();
    if (["png", "jpg", "jpeg", "gif"].includes(ext)) return "🖼️";
    if (["pdf"].includes(ext)) return "📕";
    if (["doc", "docx"].includes(ext)) return "📄";
    if (["xls", "xlsx", "csv"].includes(ext)) return "📊";
    if (["zip"].includes(ext)) return "🗜️";
    if (["json", "md", "txt"].includes(ext)) return "📝";
    return "📁";
}

function initUploadDropzone() {
    var dropzone = document.getElementById("dropzone");
    var input = document.getElementById("file");
    var form = document.getElementById("uploadForm");
    if (!dropzone || !input || !form) return;

    var preview = document.getElementById("filePreview");
    var progress = document.getElementById("uploadProgress");
    var progressFill = progress ? progress.querySelector(".progress-bar-fill") : null;
    var submitBtn = document.getElementById("uploadSubmit");

    function showPreview(file) {
        if (!preview) return;
        preview.querySelector(".fp-icon").textContent = fileIconGlyph(file.name);
        preview.querySelector(".fp-name").textContent = file.name;
        preview.querySelector(".fp-size").textContent = humanFileSize(file.size);
        preview.classList.add("show");
    }

    dropzone.addEventListener("click", function (e) {
        if (e.target.tagName !== "INPUT") input.click();
    });

    ["dragenter", "dragover"].forEach(function (evt) {
        dropzone.addEventListener(evt, function (e) {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(function (evt) {
        dropzone.addEventListener(evt, function (e) {
            e.preventDefault();
            dropzone.classList.remove("dragover");
        });
    });

    dropzone.addEventListener("drop", function (e) {
        if (e.dataTransfer.files.length) {
            input.files = e.dataTransfer.files;
            showPreview(e.dataTransfer.files[0]);
        }
    });

    input.addEventListener("change", function () {
        if (input.files.length) showPreview(input.files[0]);
    });

    form.addEventListener("submit", function (e) {
        if (!input.files.length) return; // let native "required" handle it
        e.preventDefault();

        var maxBytes = parseInt(form.dataset.maxBytes || "0", 10);
        if (maxBytes && input.files[0].size > maxBytes) {
            alert("That file is larger than the " + humanFileSize(maxBytes) + " limit.");
            return;
        }

        var xhr = new XMLHttpRequest();
        var data = new FormData(form);

        xhr.upload.addEventListener("progress", function (evt) {
            if (!evt.lengthComputable || !progress || !progressFill) return;
            progress.classList.add("show");
            progressFill.style.width = Math.round((evt.loaded / evt.total) * 100) + "%";
        });

        xhr.addEventListener("load", function () {
            // Flask followed our POST with a redirect (to My Files on
            // success, or back to the upload form with a flash error).
            // Navigating the browser there for real keeps the URL bar,
            // back button, and flash messages all behaving normally.
            window.location.href = xhr.responseURL || form.action;
        });

        xhr.addEventListener("error", function () {
            alert("Upload failed — check your connection and try again.");
            if (submitBtn) submitBtn.disabled = false;
        });

        xhr.open("POST", form.action);
        xhr.send(data);
        if (submitBtn) submitBtn.disabled = true;
        if (progress) progress.classList.add("show");
    });
}
