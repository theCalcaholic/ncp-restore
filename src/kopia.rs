

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub(crate) enum KopiaRepository {
    FILE(String, String)
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub(crate) struct KopiaConfig {
    repository: KopiaRepository,
}

