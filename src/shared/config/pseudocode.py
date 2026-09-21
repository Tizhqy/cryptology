"""PSEUDOCODE: JSON config yukleme ve validation akisinin taslagi."""


def load_settings(config_path, profile_path=None):
    # Ana JSON dosyasini oku.
    base_config = read_json(config_path)

    # Profil varsa ayarlari ana config'in uzerine birlestir.
    profile_config = read_json(profile_path) if profile_path else {}
    merged_config = deep_merge(base_config, profile_config)

    # Kodun her yerinde ham dictionary kullanmamak icin typed settings uret.
    settings = Settings.from_dict(merged_config)
    validate_settings(settings)
    return settings


def validate_settings(settings):
    # Dosya boyutu ve chunk boyutu pozitif olmali.
    require(settings.transfer.max_file_size_bytes > 0)
    require(settings.transfer.chunk_size_bytes > 0)

    # Rapor icin en az 10 tekrar zorunlu; 15 tercih edilen degerdir.
    if settings.measurement.repeat_count < 10:
        raise ConfigError("repeat_count must be at least 10")

    # Manuel AES gercek network aktariminda kullanilamaz.
    if settings.security.data_encryption.implementation == "manual":
        require(settings.security.mode == "experiment")
        require(settings.security.data_encryption.mode == "single-block")

    # Insecure profil yalnizca development/lab ortaminda acilabilir.
    if settings.security.mode == "insecure":
        require(settings.application.environment in ["development", "experiment"])

    # ML-KEM secimi provider'in kurulu olup olmadigini startup'ta kontrol eder.
    if settings.security.key_exchange == "ml-kem-768":
        check_mlkem_provider_available()
