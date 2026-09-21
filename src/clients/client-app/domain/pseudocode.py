"""PSEUDOCODE: Client domain modelleri."""


class ClientIdentity:
    def validate(self):
        # client-a ve client-b gibi sabit, anlamli kimlikleri kabul et.
        require(self.value in settings.allowed_client_ids)


class TransferPolicy:
    def validate_pdf(self, file_info):
        # Dosya tipi ve boyutu application'a gecmeden once kontrol edilir.
        require(file_info.extension == ".pdf")
        require(file_info.size <= settings.transfer.max_file_size_bytes)


class SecurityProfile:
    def allows_manual_aes(self):
        # Manuel AES, sadece experiment profile icin uygundur.
        return self.mode == "experiment" and self.implementation == "manual"
