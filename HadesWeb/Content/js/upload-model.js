function openModal() {
    document.getElementById("infoModal").style.display = "block";
}

function closeModal() {
    document.getElementById("infoModal").style.display = "none";
}

window.onclick = function (event) {
    var modal = document.getElementById("infoModal");
    if (event.target == modal) {
        modal.style.display = "none";
    }
}