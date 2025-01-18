const BASE_URL = "http://127.0.0.1:5000"; // Flask server URL

document.getElementById('download-form').style.display = 'none'
document.getElementById("search-documents").style.display = 'none'
document.getElementById("verify-form").style.display = 'none'

// document.getElementById("login-form").addEventListener("submit", async (event) => {
//     event.preventDefault();
//     const nationalId = document.getElementById("loginNationalId").value;
//     const password = document.getElementById("loginPassword").value;

//     const response = await fetch(`${BASE_URL}/login`, {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ national_id: nationalId, password }),
//     });

//     const data = await response.json();

//     if (response.ok) {
//         localStorage.setItem("token", data.access_token);
//         alert("Login successful");
//         document.getElementById("login-form").style.display = "none";
//         document.getElementById("download-form").style.display = "block";
//         document.getElementById("search-documents").style.display = "block";
//         document.getElementById("verify-form").style.display = "block";

//     } else {
//         alert(data.message || "Login failed");
//     }
// });

document.getElementById("admin-login-section").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("admin-username").value;
    const password = document.getElementById("admin-password").value;

    try {
        const response = await fetch("http://127.0.0.1:5000/admin/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();
        console.log(data)

        if (response.ok) {
            alert(data.message);
            // window.location.href = "/admin/panel"; // Redirect to admin panel
            document.getElementById("admin-login-form").style.display = "none";
            document.getElementById("download-form").style.display = "block";
            document.getElementById("search-documents").style.display = "block";
            document.getElementById("verify-form").style.display = "block";
        } else {
            alert(data.message);
        }
    } catch (error) {
        console.error("Login failed:", error);
    }
});

// Handle Document Download
document.getElementById("download-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const documentId = document.getElementById("documentId").value;

    const token = localStorage.getItem("token");
    const response = await fetch(`${BASE_URL}/download/${documentId}`, {
        method: "GET",
        headers: {
            Authorization: `Bearer ${token}`,
        },
    });

    if (response.ok) {
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = `document-${documentId}.pdf`; // Example: Replace with actual file name if available
        document.body.appendChild(a);
        a.click();
        a.remove();
        alert("Download successful");
    } else {
        const data = await response.json();
        alert(data.message || "Failed to download document");
    }
});

// document.getElementById("sign-form").addEventListener("submit", async (event) => {
//     event.preventDefault();
//     const fileInput = document.getElementById("sign-file");
//     const file = fileInput.files[0];

//     const formData = new FormData();
//     formData.append("file", file);

//     const response = await fetch(`${BASE_URL}/sign`, {
//         method: "POST",
//         body: formData,
//     });

//     const data = await response.json();
//     alert(data.message || "File signed successfully");
// });
document.getElementById("verify-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const filePath = document.getElementById("verify-file-path").value;
    const signaturePath = document.getElementById("verify-signature-path").value;

    const formData = new URLSearchParams();
    formData.append("file_path", filePath);
    formData.append("signature_path", signaturePath);

    const response = await fetch(`${BASE_URL}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData,
    });

    const data = await response.json();
    alert(data.message || "Verification complete");
});

document.getElementById("search-documents").addEventListener("click", async () => {
    const nationalId = prompt("Enter National ID to search for documents:");
    if (!nationalId) {
        alert("National ID is required!");
        return;
    }

    const token = localStorage.getItem("token"); // Admin token for authentication
    const response = await fetch(`${BASE_URL}/admin/search?national_id=${encodeURIComponent(nationalId)}`, {
        method: "GET",
        headers: {
            Authorization: `Bearer ${token}`, // Add token for secure access
        },
    });

    if (response.ok) {
        const data = await response.json();
        const resultsContainer = document.getElementById("search-results");
        resultsContainer.innerHTML = "";

        if (data.results && data.results.length > 0) {
            data.results.forEach((doc) => {
                const docItem = document.createElement("div");
                docItem.classList.add("card", "mb-3");
                docItem.innerHTML = `
                    <div class="card-body">
                        <h5 class="card-title">Document ID: ${doc.id}</h5>
                        <p class="card-text">
                           <strong>File Name:</strong> ${doc.file_name}<br>
                           <strong>Uploaded At:</strong> ${doc.uploaded_at}<br>
                           <strong>File Path:</strong> ${doc.file_path}
                        </p>
                    </div>
                `;
                resultsContainer.appendChild(docItem);
            });
        } else {
            resultsContainer.innerHTML = "<p>No documents found for the provided National ID.</p>";
        }
    } else {
        const error = await response.json();
        alert(error.message || "Failed to fetch documents");
    }
});
