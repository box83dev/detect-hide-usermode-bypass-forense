#include <unhide/models.h>

namespace unhide {
namespace modelos {

std::string textoVeredito(NivelVeredito v) {
    if (v == NivelVeredito::Confirmado) {
        return "CONFIRMED";
    }
    if (v == NivelVeredito::Suspeito) {
        return "SUSPICIOUS";
    }
    if (v == NivelVeredito::Informativo) {
        return "INFORMATIVE";
    }
    return "CLEAN";
}

}
}
