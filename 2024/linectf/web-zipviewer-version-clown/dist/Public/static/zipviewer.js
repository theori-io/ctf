function Enter() {
    const filename = document.getElementById("username").value
    const url = `/enter/${filename}`

    fetch(url, {
        method: "GET",
    })
    .then((response) => {
        if (!response.ok) {
            throw new Error(`${response.statusText}`);
        }

        return response.json()
    })
    .then(data => {
        alert(data.message)
        window.location.href = "/viewer"
    })
    .catch((error) => {
        alert(error);
    })
}

function ZipFileUpload() {
    const formData = new FormData()
    const zipfile = document.querySelector("#zipfile").files[0];

    formData.append("data", zipfile);

    fetch("/upload", {
        method: "POST",
        body: formData,
    })
    .then((response) => {
        if (!response.ok) {
            throw new Error(`${response.statusText}`);
        }
        
        alert(response.statusText);
    })
    .catch((error) => {
        alert(error);
    })
    .finally(() => {
        window.location.href = '/viewer';
    });
}

function ClearSessionAndFiles() {
    fetch("/clear", {
        method: "DELETE",
    })
    .then((response) => {
        if (!response.ok) {
            throw new Error(`${response.statusText}`);
        }
        
        alert(response.statusText);
    })
    .catch((error) => {
        alert(error);
    })
    .finally(() => {
        window.location.href = '/';
    });
}

function DownloadFile(filename) {
    let url = `/download/${filename}`

    fetch(url, {
        method: "GET",
    })
    .then((response) => {
        if (!response.ok) {
            throw new Error(`${response.statusText}`);
        }
    })
    .catch((error) => {
        alert(error);
        window.location.href = '/viewer';
    });
}