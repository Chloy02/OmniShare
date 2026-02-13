const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let isRunning = false;
let toggleBtn;
let currentTransferId = null;

async function checkStatus() {
  try {
    isRunning = await invoke("is_receiver_running");
    updateUI();
  } catch (error) {
    console.error("Failed to check status:", error);
  }
}

async function toggleReceiver() {
  try {
    if (isRunning) {
      await invoke("stop_receiver");
      isRunning = false;
    } else {
      await invoke("start_receiver");
      isRunning = true;
    }
    updateUI();
  } catch (error) {
    console.error("Failed to toggle receiver:", error);
    alert("Error: " + error);
  }
}

function updateUI() {
  if (isRunning) {
    toggleBtn.textContent = "Stop Receiver";
    toggleBtn.classList.remove("bg-blue-600", "hover:bg-blue-500", "shadow-blue-500/25");
    toggleBtn.classList.add("bg-red-600", "hover:bg-red-500", "shadow-red-500/25");
  } else {
    toggleBtn.textContent = "Start Receiver";
    toggleBtn.classList.remove("bg-red-600", "hover:bg-red-500", "shadow-red-500/25");
    toggleBtn.classList.add("bg-blue-600", "hover:bg-blue-500", "shadow-blue-500/25");
  }
}

function formatBytes(bytes, decimals = 2) {
  if (!+bytes) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

async function setupListeners() {
  // Listen for Transfer Requests
  await listen('transfer-request', (event) => {
    console.log("Received transfer request:", event);
    const req = event.payload;
    currentTransferId = req.id;

    // Update Modal Content
    document.getElementById('modal-sender').textContent = req.sender_name;
    const fileList = document.getElementById('modal-files');
    fileList.innerHTML = req.files.map(f => `
      <li class="flex justify-between items-center text-sm p-2 bg-slate-800 rounded-lg">
        <span class="truncate pr-2 text-slate-200">${f.name}</span>
        <span class="text-slate-400 whitespace-nowrap font-mono text-xs">${formatBytes(f.size)}</span>
      </li>
    `).join('');

    // Show Modal
    document.getElementById('transfer-modal').classList.remove('hidden');
    // Reset Progress UI
    document.getElementById('progress-container').classList.add('hidden');
    document.getElementById('modal-actions').classList.remove('hidden');
  });

  // Listen for Progress Updates
  await listen('transfer-progress', (event) => {
    const p = event.payload;
    console.log(`EVENT: Received progress for ID ${p.id} (${p.progress.toFixed(1)}%)`, p);

    if (currentTransferId) {
      console.log(`UI: Current ID ${currentTransferId} (type: ${typeof currentTransferId}) vs Received ID ${p.id} (type: ${typeof p.id})`);
    } else {
      console.log("UI: No current transfer ID active.");
    }

    // Only show progress for current active transfer
    if (currentTransferId && p.id === currentTransferId) {
      const container = document.getElementById('progress-container');
      const actions = document.getElementById('modal-actions');

      if (container.classList.contains('hidden')) {
        container.classList.remove('hidden');
        actions.classList.add('hidden'); // Hide buttons during transfer
      }

      // Update Bar Width
      const bar = document.getElementById('progress-bar');
      bar.style.width = `${p.progress}%`;

      // Update Text
      document.getElementById('progress-percent').textContent = `${p.progress.toFixed(1)}%`;
      document.getElementById('progress-transferred').textContent =
        `${formatBytes(p.bytes_transferred)} / ${formatBytes(p.total_bytes)}`;

      // Completion State
      if (p.progress >= 100) {
        console.log("UI: Transfer complete. Resetting modal.");
        document.getElementById('progress-status').textContent = "Transfer Complete!";
        document.getElementById('progress-status').classList.add('text-green-400');
        bar.classList.add('bg-green-500');

        // Close modal after delay
        setTimeout(() => {
          closeModal();
          // Reset UI for next time
          bar.classList.remove('bg-green-500');
          document.getElementById('progress-status').classList.remove('text-green-400');
          document.getElementById('progress-status').textContent = "Receiving...";
        }, 3000);
      }
    } else {
      if (p.id !== currentTransferId) {
        console.warn(`UI: Ignored progress event. ID mismatch. Expected ${currentTransferId}, got ${p.id}`);
      }
    }
  });
}

function closeModal() {
  document.getElementById('transfer-modal').classList.add('hidden');
  currentTransferId = null;
}

window.addEventListener("DOMContentLoaded", () => {
  toggleBtn = document.querySelector("#toggle-receiver-btn");
  toggleBtn.addEventListener("click", toggleReceiver);

  document.querySelector("#settings-btn").addEventListener("click", () => {
    console.log("Settings clicked");
  });

  // Modal Buttons
  document.getElementById("modal-accept").addEventListener("click", async () => {
    if (currentTransferId) {
      try {
        await invoke("accept_transfer", { transferId: currentTransferId });
        // Don't close modal! Show progress instead.
        document.getElementById('modal-actions').classList.add('hidden');
        document.getElementById('progress-container').classList.remove('hidden');
      } catch (e) {
        console.error("Accept failed:", e);
        alert("Failed to accept: " + e);
      }
    }
  });

  document.getElementById("modal-reject").addEventListener("click", async () => {
    if (currentTransferId) {
      try {
        await invoke("reject_transfer", { transferId: currentTransferId });
        closeModal();
      } catch (e) {
        console.error("Reject failed:", e);
      }
    }
  });

  // Initial setup
  checkStatus();
  setupListeners();
});
