<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__.'/src')
    ->append([__DIR__.'/.php-cs-fixer.dist.php']);

$config = new PhpCsFixer\Config();
$config
    ->setUsingCache(false)
    ->setRules([
        '@Symfony' => true,
        '@Symfony:risky' => true,
        '@auto' => true,
        '@auto:risky' => true,
        'blank_line_before_statement' => false,
        'class_attributes_separation' => true,
        'combine_consecutive_issets' => true,
        'combine_consecutive_unsets' => true,
        'concat_space' => ['spacing' => 'none'],
        'declare_strict_types' => false,
        'method_chaining_indentation' => true,
        'multiline_whitespace_before_semicolons' => true,
        'native_constant_invocation' => false,
        'native_function_invocation' => false,
        'no_alternative_syntax' => ['fix_non_monolithic_code' => false],
        'no_superfluous_elseif' => true,
        'operator_linebreak' => ['only_booleans' => true, 'position' => 'end'],
        'single_line_throw' => false,
        'trailing_comma_in_multiline' => ['after_heredoc' => true, 'elements' => ['array_destructuring', 'arrays']],
        'void_return' => false,
        'yoda_style' => false,
    ])
    ->setFinder($finder);

return $config;
