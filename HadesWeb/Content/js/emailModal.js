function openModal(title, date, text) {
    var modal = document.getElementById("emailModal");
    modal.style.display = "block";

    document.getElementById("modalTitle").innerText = title;
    document.getElementById("modalDate").innerText = date;
    document.getElementById("modalText").innerText = text;
}

var span = document.getElementsByClassName("close")[0];
span.onclick = function () {
    var modal = document.getElementById("emailModal");
    modal.style.display = "none";
}

window.onclick = function (event) {
    var modal = document.getElementById("emailModal");
    if (event.target == modal) {
        modal.style.display = "none";
    }
}