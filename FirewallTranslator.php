<?php

namespace XcVm\Module\Firewall;

use ReflectionClass;
use XcVm\Core\Localization\Translator;

/**
 * FirewallTranslator — Localization loader and bridge for Firewall & Fail2ban Module.
 *
 * Provides complete translation management for English (en) and Arabic (ar).
 * Bridges seamlessly with XcVm\Core\Localization\Translator without altering
 * any core panel files, injecting module dictionaries dynamically.
 *
 * @package XC_VM_Module_Firewall
 */
class FirewallTranslator {

	private static bool $initialized = false;
	private static ?string $injectedLang = null;
	/** @var array<string, string> */
	private static array $cachedTranslations = [];
	private static string $langDir = __DIR__ . '/lang/';

	/**
	 * Initialize and bridge module translations into the runtime Translator.
	 */
	public static function init(): void {
		$currentLang = class_exists(Translator::class) ? Translator::current() : 'en';

		if (self::$initialized && self::$injectedLang === $currentLang) {
			return;
		}

		$enData = self::loadFile('en');
		$currentData = ($currentLang !== 'en') ? self::loadFile($currentLang) : $enData;

		// Fallback missing keys in the current language to English
		$mergedCurrent = array_merge($enData, $currentData);
		self::$cachedTranslations = $mergedCurrent;

		// Bridge dynamically into core Translator
		if (class_exists(Translator::class)) {
			try {
				$ref = new ReflectionClass(Translator::class);

				// Inject current translations
				if ($ref->hasProperty('translations')) {
					$propTrans = $ref->getProperty('translations');
					$propTrans->setAccessible(true);
					$existingTrans = $propTrans->getValue() ?: [];
					$propTrans->setValue(null, array_merge($mergedCurrent, $existingTrans));
				}

				// Inject English dictionary for fallback & Translations page
				if ($ref->hasProperty('enTranslations')) {
					$propEn = $ref->getProperty('enTranslations');
					$propEn->setAccessible(true);
					$existingEn = $propEn->getValue();
					if ($existingEn === null) {
						$existingEn = Translator::englishTranslations();
					}
					$propEn->setValue(null, array_merge($enData, $existingEn));
				}
			} catch (\Throwable $e) {
				error_log('FirewallTranslator: failed to bridge into core Translator: ' . $e->getMessage());
			}
		}

		self::$initialized = true;
		self::$injectedLang = $currentLang;
	}

	/**
	 * Read and parse a language .ini file from the module's lang directory.
	 *
	 * @param string $lang Two-letter language code (e.g. 'en', 'ar')
	 * @return array<string, string>
	 */
	public static function loadFile(?string $lang): array {
		$lang = $lang ?: 'en';
		$file = self::$langDir . $lang . '.ini';
		if (is_file($file) && is_readable($file)) {
			$data = @parse_ini_file($file, false, INI_SCANNER_RAW);
			if (is_array($data)) {
				return $data;
			}
		}
		return [];
	}

	/**
	 * Retrieve a translated string by key with optional replacements or fallback string.
	 *
	 * @param ?string $key Translation key
	 * @param array<string, string>|string $replace Substitutions for strtr() or default fallback string
	 * @return string
	 */
	public static function get(?string $key, array|string $replace = []): string {
		if ($key === null || $key === '') {
			return is_string($replace) ? $replace : '';
		}

		if (!self::$initialized) {
			self::init();
		}

		$fallback = is_string($replace) ? $replace : $key;
		$text = self::$cachedTranslations[$key] ?? $fallback;

		if (is_array($replace) && !empty($replace)) {
			$text = strtr($text, $replace);
		}

		return $text;
	}
}
