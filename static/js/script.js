// Script pour valider le numéro de téléphone
function validatePhoneNumber() {
    const phoneNumber = document.getElementById('phone_number').value;
    const errorMsg = document.getElementById('phone-error');

    // Vérifier que le numéro contient exactement 8 chiffres
    const phoneRegex = /^[0-9]{8}$/;
    if (!phoneRegex.test(phoneNumber)) {
        errorMsg.style.display = 'block'; // Affiche le message d'erreur
        return false; // Empêche la soumission du formulaire
    } else {
        errorMsg.style.display = 'none'; // Masque le message d'erreur si tout est correct
        return true; // Autorise la soumission du formulaire
    }
}
