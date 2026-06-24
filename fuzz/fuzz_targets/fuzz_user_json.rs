#![no_main]

use libfuzzer_sys::fuzz_target;
use rullst_connect::user::ConnectUser;

fuzz_target!(|data: &[u8]| {
    // Alvo: Testar a robustez do parser JSON para perfis de usuário OAuth.
    // Provedores diferentes podem retornar tipos de dados imprevistos ou campos
    // ausentes. Isso garante que a biblioteca retorne um erro amigável (Err)
    // ao invés de derrubar o servidor em pânico.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<ConnectUser>(s);
    }
});
