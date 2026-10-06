<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * `tokens.token` era `unique`: os códigos usados nunca saem da tabela, então
 * sortear um código que já existe ficava cada vez mais provável e a gravação de
 * um código novo falhava. A busca é sempre por destinatário + código (hash), e
 * o índice composto atende a ela.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('tokens', function (Blueprint $table) {
            $table->dropUnique(['token']);
            $table->index(['authenticatable_id', 'token']);
        });
    }

    public function down(): void
    {
        Schema::table('tokens', function (Blueprint $table) {
            $table->dropIndex(['authenticatable_id', 'token']);
            $table->unique('token');
        });
    }
};
