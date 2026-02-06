const { invoke } = window.__TAURI__.core;

let isRunning = false;
let toggleBtn;

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

window.addEventListener("DOMContentLoaded", () => {
  toggleBtn = document.querySelector("#toggle-receiver-btn");

  toggleBtn.addEventListener("click", toggleReceiver);
  document.querySelector("#settings-btn").addEventListener("click", () => {
    // TODO: Open settings
    console.log("Settings clicked");
  });

  // Check initial status
  checkStatus();
});
