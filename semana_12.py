import csv
import hashlib
import hmac
import itertools
import json
import os
import re
import secrets
import sys
from collections import Counter
from datetime import date, datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config_privacidad.json"


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def parse_date(value):
    if not value:
        return None
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        return None


def normalize(value):
    return (value or "").strip().casefold()


def consent_is_given(value):
    return normalize(value) in {"si", "sí", "yes", "true", "1", "consentido"}


def age_on(birth_date, reference_date):
    years = reference_date.year - birth_date.year
    if (reference_date.month, reference_date.day) < (
        birth_date.month,
        birth_date.day,
    ):
        years -= 1
    return years


def age_band(age, limits, labels):
    for index in range(len(labels)):
        if limits[index] <= age < limits[index + 1]:
            return labels[index]
    return "Edad desconocida"


def compile_patterns(config):
    return {
        name: re.compile(pattern, re.IGNORECASE)
        for name, pattern in config["patrones_pii"].items()
    }


def detect_pii(rows, fieldnames, patterns):
    detected = {}
    for kind, pattern in patterns.items():
        by_column = {}
        for field in fieldnames:
            count = sum(
                len(pattern.findall(row.get(field, "") or "")) for row in rows
            )
            if count:
                by_column[field] = count
        if by_column:
            detected[kind] = {
                "columnas": by_column,
                "clasificacion": "identificador directo",
            }
    return detected


def classify_columns(fieldnames, config, detected):
    direct_names = {"id_cliente", "nombre", "rut", "email", "telefono"}
    quasi_names = set(config.get("cuasi_identificadores", []))
    quasi_names.add("tramo_edad")
    quasi_names.add(config["columna_fecha_nacimiento"])
    text_fields = set(config.get("columnas_texto_libre", []))
    classifications = {}
    for field in fieldnames:
        if field in direct_names or field in {
            config.get("columna_rut"),
            config.get("columna_pseudonimo"),
        }:
            classifications[field] = "identificador directo"
        elif field in quasi_names:
            classifications[field] = "cuasi-identificador"
        else:
            classifications[field] = "otro dato"
    for details in detected.values():
        for field in details["columnas"]:
            if field not in quasi_names and field not in {
                config.get("columna_pseudonimo")
            }:
                classifications[field] = (
                    "texto libre con identificadores directos detectados"
                    if field in text_fields
                    else "identificador directo (PII detectada)"
                )
    return classifications


def quasi_records(rows, config, reference_date, age_levels, comuna_level, sex_level):
    limits = config["tramos_edad"]["limites"]
    labels = config["tramos_edad"]["etiquetas"]
    comuna_field = config["cuasi_identificadores"][0]
    sex_field = config["cuasi_identificadores"][2]
    birth_field = config["columna_fecha_nacimiento"]
    result = []

    for source in rows:
        row = dict(source)
        birth = parse_date(row.get(birth_field, ""))
        age = age_on(birth, reference_date) if birth else None
        band = age_band(age, limits, labels) if age is not None else "Edad desconocida"
        if age_levels == 1:
            band = "Todas las edades"

        comuna = (row.get(comuna_field) or "").strip() or "Desconocida"
        if comuna_level == 1:
            comuna = "Comunas agrupadas"
        elif comuna_level == 2:
            comuna = "Todas"

        sex = (row.get(sex_field) or "").strip() or "Desconocido"
        if sex_level == 1:
            sex = "Todos"

        row["tramo_edad"] = band
        row[comuna_field] = comuna
        row[sex_field] = sex
        result.append(row)
    return result


def anonymity_metrics(rows, quasi_fields):
    if not rows:
        return {"k_minimo_observado": 0, "porcentaje_registros_unicos": 0.0}
    classes = Counter(tuple(row.get(field, "") for field in quasi_fields) for row in rows)
    smallest_class = min(classes.values())
    unique_records = sum(size for size in classes.values() if size == 1)
    return {
        "k_minimo_observado": smallest_class,
        "porcentaje_registros_unicos": round(100 * unique_records / len(rows), 2),
    }


def privacy_metrics(rows, config, reference_date):
    consent_field = config["columna_consentimiento"]
    registration_field = config["columna_fecha_registro"]
    cutoff = reference_date - timedelta(days=config["retencion_dias"])
    no_consent = sum(
        not consent_is_given(row.get(consent_field, "")) for row in rows
    )
    expired = 0
    invalid_registration_dates = 0
    for row in rows:
        registered = parse_date(row.get(registration_field, ""))
        if registered is None:
            invalid_registration_dates += 1
        elif registered < cutoff:
            expired += 1
    return {
        "registros": len(rows),
        "registros_sin_consentimiento": no_consent,
        "registros_que_superan_retencion": expired,
        "fechas_registro_invalidas_o_ausentes": invalid_registration_dates,
    }


def pseudonymize(value, salt):
    canonical_rut = re.sub(r"[.\-\s]", "", (value or "").strip()).upper()
    return hmac.new(salt, canonical_rut.encode("utf-8"), hashlib.sha256).hexdigest()


def redact_text(value, patterns):
    text = value or ""
    for pattern in patterns.values():
        text = pattern.sub("[DATO ELIMINADO]", text)
    return text


def create_output_rows(rows, config, patterns, salt, direct_fields):
    remove_fields = set(config.get("columnas_a_eliminar", []))
    remove_fields.update(
        {
            config["columna_rut"],
            config["columna_fecha_nacimiento"],
            config["columna_consentimiento"],
            config["columna_fecha_registro"],
        }
    )
    text_fields = set(config.get("columnas_texto_libre", []))
    pseudo_field = config["columna_pseudonimo"]
    rut_field = config["columna_rut"]
    remove_fields.update(
        field
        for field in direct_fields
        if field not in text_fields and field != rut_field
    )
    output = []

    for row in rows:
        cleaned = {
            key: redact_text(value, patterns) if key in text_fields else value
            for key, value in row.items()
            if key not in remove_fields
        }
        cleaned[pseudo_field] = pseudonymize(row.get(rut_field, ""), salt)
        output.append(cleaned)
    return output


def main():
    config = load_config()
    input_path = BASE_DIR / config["archivo_entrada"]
    output_path = BASE_DIR / config["archivo_salida"]
    report_path = BASE_DIR / config["archivo_informe"]
    reference_date = date.fromisoformat(config["fecha_referencia"])
    cutoff = reference_date - timedelta(days=config["retencion_dias"])

    with input_path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        fieldnames = reader.fieldnames or []
        input_rows = list(reader)
    if not fieldnames:
        raise ValueError(f"No se encontraron encabezados en {input_path.name}.")

    patterns = compile_patterns(config)
    detected_before = detect_pii(input_rows, fieldnames, patterns)
    classifications = classify_columns(fieldnames, config, detected_before)
    quasi_fields = [
        config["cuasi_identificadores"][0],
        "tramo_edad",
        config["cuasi_identificadores"][2],
    ]
    source_with_quasi = quasi_records(input_rows, config, reference_date, 0, 0, 0)
    metrics_before = privacy_metrics(input_rows, config, reference_date)
    metrics_before.update(anonymity_metrics(source_with_quasi, quasi_fields))

    eligible_rows = []
    removed_no_consent = 0
    removed_retention = 0
    removed_invalid_date = 0
    for row in input_rows:
        registered = parse_date(row.get(config["columna_fecha_registro"], ""))
        if not consent_is_given(row.get(config["columna_consentimiento"], "")):
            removed_no_consent += 1
        elif registered is None:
            removed_invalid_date += 1
        elif registered < cutoff:
            removed_retention += 1
        else:
            eligible_rows.append(row)

    selected = None
    selected_levels = None
    # Increase generalization only as much as needed to meet the configured k.
    candidates = sorted(
        itertools.product(range(3), range(2), range(2)),
        key=lambda levels: (sum(levels), levels),
    )
    for comuna_level, age_level, sex_level in candidates:
        candidate = quasi_records(
            eligible_rows,
            config,
            reference_date,
            age_level,
            comuna_level,
            sex_level,
        )
        if anonymity_metrics(candidate, quasi_fields)["k_minimo_observado"] >= config[
            "k_minimo"
        ]:
            selected = candidate
            selected_levels = {
                "comuna": comuna_level,
                "tramo_edad": age_level,
                "sexo": sex_level,
            }
            break
    if selected is None:
        raise ValueError(
            "No fue posible alcanzar el k mínimo configurado con las "
            "generalizaciones disponibles."
        )

    salt_variable = config["variable_sal"]
    configured_salt = os.environ.get(salt_variable)
    salt = (
        configured_salt.encode("utf-8")
        if configured_salt
        else secrets.token_bytes(32)
    )
    salt_source = "variable de entorno" if configured_salt else "aleatoria en memoria"
    direct_fields = {
        field
        for field, classification in classifications.items()
        if classification.startswith("identificador directo")
    }
    output_rows = create_output_rows(
        selected, config, patterns, salt, direct_fields
    )

    output_fields = []
    for row in output_rows:
        for field in row:
            if field not in output_fields:
                output_fields.append(field)
    if output_rows:
        with output_path.open("w", encoding="utf-8-sig", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=output_fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(output_rows)
    else:
        raise ValueError("No quedan registros elegibles para generar el archivo de salida.")

    detected_after = detect_pii(
        output_rows,
        [field for field in output_fields if field != config["columna_pseudonimo"]],
        patterns,
    )
    after_metrics = anonymity_metrics(output_rows, quasi_fields)
    metrics_after = {
        "registros": len(output_rows),
        "registros_sin_consentimiento": 0,
        "registros_que_superan_retencion": 0,
        **after_metrics,
    }
    if detected_after:
        raise ValueError(
            "La verificación encontró patrones de PII en la salida: "
            + ", ".join(detected_after)
        )
    if after_metrics["k_minimo_observado"] < config["k_minimo"]:
        raise ValueError("La salida no cumple el k mínimo configurado.")

    report = {
        "fecha_ejecucion": datetime.now().astimezone().isoformat(timespec="seconds"),
        "fecha_referencia": config["fecha_referencia"],
        "politica": {
            "k_minimo": config["k_minimo"],
            "retencion_dias": config["retencion_dias"],
            "fecha_limite_retencion": cutoff.isoformat(),
        },
        "deteccion_pii_antes": {
            "clasificacion_columnas": classifications,
            "patrones": detected_before,
            "texto_libre_analizado": config.get("columnas_texto_libre", []),
        },
        "evaluacion_antes": metrics_before,
        "mitigacion": {
            "registros_eliminados_sin_consentimiento": removed_no_consent,
            "registros_eliminados_por_retencion": removed_retention,
            "registros_eliminados_por_fecha_invalida": removed_invalid_date,
            "generalizacion_aplicada": selected_levels,
            "rut": "HMAC-SHA256; el RUT original no se conserva",
            "sal_pseudonimizacion": salt_source,
            "identificadores_directos": "eliminados; PII en texto libre redactada",
        },
        "evaluacion_despues": metrics_after,
        "verificacion": {
            "k_minimo_cumplido": metrics_after["k_minimo_observado"]
            >= config["k_minimo"],
            "sin_patrones_pii_detectables": not detected_after,
            "sin_registros_sin_consentimiento": True,
            "sin_registros_fuera_de_retencion": True,
            "columnas_salida": output_fields,
        },
        "principios_aplicados": [
            "Finalidad y limitación del tratamiento: conservar solo los campos necesarios para el análisis.",
            "Minimización de datos: retirar identificadores directos y redactar PII en texto libre.",
            "Limitación del plazo de conservación: eliminar registros fuera de retención.",
            "Consentimiento: excluir registros sin consentimiento afirmativo.",
            "Seguridad y confidencialidad: pseudonimizar el RUT con HMAC y no guardar la sal.",
            "Privacidad desde el diseño: generalizar cuasi-identificadores hasta alcanzar k-anonimato.",
        ],
        "riesgo_residual": [
            "La pseudonimización no es anonimización irreversible: con la sal adecuada o datos auxiliares podría vincularse una persona.",
            "La generalización reduce pero no elimina el riesgo de reidentificación por combinación con fuentes externas.",
            "Los patrones regex detectan formatos conocidos; no garantizan encontrar nombres u otros datos identificadores escritos de forma atípica.",
            "El gasto mensual puede ser sensible y permitir inferencias; su conservación debe justificarse y restringirse.",
        ],
    }
    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
        file.write("\n")

    print(f"CSV anonimizado: {output_path.name}")
    print(f"Informe antes/después: {report_path.name}")
    print(
        "Resultado: "
        f"{metrics_after['registros']} registros, "
        f"k={metrics_after['k_minimo_observado']}, "
        f"{metrics_after['porcentaje_registros_unicos']}% únicos."
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError, csv.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
