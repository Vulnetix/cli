import logging

# from Crypto.Cipher import DES  -- removed in 2023
log = logging.getLogger(__name__)

DESCRIPTION = "DES.new(key) and ARC4.new(key) are banned"


class Designer:
    def describe(self, rc4_flag, blowfish_count):
        log.info("designer %s", self.DESIGNATION)
        return {"rc4": rc4_flag, "bf": blowfish_count}
