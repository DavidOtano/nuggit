#ifndef NG_WPNP_CRYPT_H
#define NG_WPNP_CRYPT_H

#include <cstdint>
#include <string>

namespace ng::wpn::crypt {

namespace frontcode {
void encrypt(const uint8_t* src, uint8_t* dst);
void decrypt(const uint8_t* src, uint8_t* dst);
}  // namespace frontcode

namespace tcp {
uint16_t get_crypt_key_id(const uint8_t* block);
void create_crypt_key_id(uint16_t id, uint8_t* block);
uint16_t get_crypt_key(const uint8_t* block, uint32_t* up_key,
                       uint32_t* down_key);
uint32_t encrypt(uint8_t* buffer, int length, uint32_t up_key);
uint32_t decrypt(uint8_t* buffer, int length, uint32_t down_key);
void create_genac_key(uint8_t* ac);
void km_mangle_nonsense(uint8_t* block);
}  // namespace tcp

namespace udp {
void encrypt(uint8_t* buffer, int length);
void decrypt(uint8_t* buffer, int length);
}  // namespace udp

namespace filesystem {
bool get_file_hash(const std::string& file_path, uint32_t* hash,
                   uint32_t* length);
}

}  // namespace ng::wpn::crypt

#endif
