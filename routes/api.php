<?php

use CA\Cms\Http\Controllers\CmsController;
use Illuminate\Support\Facades\Route;

Route::post('/sign', [CmsController::class, 'sign'])->name('ca.cms.sign');
Route::post('/verify', [CmsController::class, 'verify'])->name('ca.cms.verify');
Route::post('/encrypt', [CmsController::class, 'encrypt'])->name('ca.cms.encrypt');
Route::post('/decrypt', [CmsController::class, 'decrypt'])->name('ca.cms.decrypt');
