const BASE_URL = "https://127.0.0.1:5000"; // Flask server URL

document.getElementById('upload-section').style.display='none'

// Handle Registration
document.getElementById("register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = document.getElementById("name").value;
    const nationalId = document.getElementById("nationalId").value;
    const phone = document.getElementById("phone").value;
    const password = document.getElementById("password").value;

    const response = await fetch(`${BASE_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, national_id: nationalId, phone, password }),
    });

    const data = await response.json();
    alert(data.message || "Registration successful");
});

// Handle Login
document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const nationalId = document.getElementById("loginNationalId").value;
    const password = document.getElementById("loginPassword").value;

    const response = await fetch(`${BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ national_id: nationalId, password }),
    });

    const data = await response.json();

    if (response.ok) {
        localStorage.setItem("token", data.access_token);
        alert("Login successful");
        document.getElementById("login-form").style.display = "none";
        document.getElementById("register-form").style.display = "none";
        document.getElementById("upload-section").style.display = "block";
        document.getElementById("download-section").style.display = "block";
        document.getElementById("verify-section").style.display = "block";

    } else {
        alert(data.message || "Login failed");
    }
});

// Handle File Upload
document.getElementById("upload-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const fileInput = document.getElementById("file");
    const file = fileInput.files[0];

    const formData = new FormData();
    formData.append("file", file);

    const token = localStorage.getItem("token");
    const response = await fetch(`${BASE_URL}/upload`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${token}`,
        },
        body: formData,
    });
    const response2 = await fetch(`${BASE_URL}/sign`, {
        method: "POST",
        body: formData,
    });
    const data = await response.json();
    if (response.ok) {
        const data2 = await response2.json();
        alert(data2.message || "File signed successfully");
        document.getElementById("sign-section").style.display = "block";
    }
    alert(data.message || "File uploaded successfully");
});



// Handle Document Download
// document.getElementById("download-form").addEventListener("submit", async (event) => {
//     event.preventDefault();
//     const documentId = document.getElementById("documentId").value;

//     const token = localStorage.getItem("token");
//     const response = await fetch(`${BASE_URL}/download/${documentId}`, {
//         method: "GET",
//         headers: {
//             Authorization: `Bearer ${token}`,
//         },
//     });

//     if (response.ok) {
//         const blob = await response.blob();
//         const downloadUrl = window.URL.createObjectURL(blob);
//         const a = document.createElement("a");
//         a.href = downloadUrl;
//         a.download = `document-${documentId}.pdf`; // Example: Replace with actual file name if available
//         document.body.appendChild(a);
//         a.click();
//         a.remove();
//         alert("Download successful");
//     } else {
//         const data = await response.json();
//         alert(data.message || "Failed to download document");
//     }
// });

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


// Handle Admin Search
// document.getElementById("search-documents").addEventListener("click", async () => {
//     const token = localStorage.getItem("token");

//     const response = await fetch(`${BASE_URL}/admin/search`, {
//         method: "GET",
//         headers: {
//             Authorization: `Bearer ${token}`,
//         },
//     });

//     if (response.ok) {
//         const data = await response.json();
//         const resultsContainer = document.getElementById("search-results");
//         resultsContainer.innerHTML = ""; // Clear previous results

//         data.results.forEach((doc) => {
//             const docItem = document.createElement("div");
//             docItem.classList.add("card", "mb-2");
//             docItem.innerHTML = `
//                 <div class="card-body">
//                     <h5 class="card-title">Document ID: ${doc.id}</h5>
//                     <p class="card-text">
//                         Owner ID: ${doc.owner_id}<br>
//                         File Name: ${doc.file_name}<br>
//                         Uploaded At: ${new Date(doc.uploaded_at).toLocaleString()}
//                     </p>
//                 </div>
//             `;
//             resultsContainer.appendChild(docItem);
//         });
//     } else {
//         alert("Failed to fetch documents");
//     }
// });
