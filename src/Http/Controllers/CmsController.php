<?php

declare(strict_types=1);

namespace CA\Cms\Http\Controllers;

use CA\Cms\Contracts\CmsEncryptorInterface;
use CA\Cms\Contracts\CmsSignerInterface;
use CA\Crt\Models\Certificate;
use CA\Key\Contracts\KeyManagerInterface;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Validator;
use Throwable;

class CmsController extends Controller
{
    public function __construct(
        private readonly CmsSignerInterface $signer,
        private readonly CmsEncryptorInterface $encryptor,
        private readonly KeyManagerInterface $keyManager,
    ) {}

    /**
     * Sign data or an uploaded file, returning DER-encoded CMS SignedData.
     */
    public function sign(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'cert_uuid' => 'required|string|uuid',
            'data' => 'required_without:file|string',
            'file' => 'required_without:data|file',
            'detached' => 'sometimes|boolean',
            'hash' => 'sometimes|string|in:sha256,sha384,sha512,sha1',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        try {
            $cert = Certificate::where('uuid', $request->input('cert_uuid'))->firstOrFail();
            $key = $this->keyManager->decryptPrivateKey($cert->key);

            $data = $request->hasFile('file')
                ? $request->file('file')->getContent()
                : $request->input('data');

            $detached = $request->boolean('detached', false);
            $options = [
                'hash' => $request->input('hash', config('ca-cms.default_hash', 'sha256')),
                'include_certs' => config('ca-cms.include_certs', true),
                'include_chain' => config('ca-cms.include_chain', false),
            ];

            $cms = $detached
                ? $this->signer->signDetached($data, $cert, $key, $options)
                : $this->signer->sign($data, $cert, $key, $options);

            return response()->json([
                'success' => true,
                'cms' => base64_encode($cms),
                'detached' => $detached,
            ]);
        } catch (Throwable $e) {
            return response()->json([
                'success' => false,
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Verify a CMS SignedData structure.
     */
    public function verify(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'cms' => 'required|string',
            'content' => 'sometimes|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        try {
            $cmsDer = base64_decode($request->input('cms'), strict: true);
            if ($cmsDer === false) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid base64-encoded CMS data.',
                ], 422);
            }

            $content = $request->has('content') ? $request->input('content') : null;

            $valid = $this->signer->verify($cmsDer, $content);

            return response()->json([
                'success' => true,
                'valid' => $valid,
            ]);
        } catch (Throwable $e) {
            return response()->json([
                'success' => false,
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Encrypt data for the given recipient certificates.
     */
    public function encrypt(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'data' => 'required|string',
            'recipient_uuids' => 'required|array|min:1',
            'recipient_uuids.*' => 'string|uuid',
            'algorithm' => 'sometimes|string|in:aes-256-cbc,aes-128-cbc,aes-192-cbc',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        try {
            $recipientCerts = Certificate::whereIn('uuid', $request->input('recipient_uuids'))->get()->all();

            if (empty($recipientCerts)) {
                return response()->json([
                    'success' => false,
                    'error' => 'No valid recipient certificates found.',
                ], 422);
            }

            $cms = $this->encryptor->encrypt($request->input('data'), $recipientCerts, [
                'encryption' => $request->input('algorithm', config('ca-cms.default_encryption', 'aes-256-cbc')),
            ]);

            return response()->json([
                'success' => true,
                'cms' => base64_encode($cms),
            ]);
        } catch (Throwable $e) {
            return response()->json([
                'success' => false,
                'error' => $e->getMessage(),
            ], 500);
        }
    }

    /**
     * Decrypt a CMS EnvelopedData structure.
     */
    public function decrypt(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'cms' => 'required|string',
            'cert_uuid' => 'required|string|uuid',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        try {
            $cmsDer = base64_decode($request->input('cms'), strict: true);
            if ($cmsDer === false) {
                return response()->json([
                    'success' => false,
                    'error' => 'Invalid base64-encoded CMS data.',
                ], 422);
            }

            $cert = Certificate::where('uuid', $request->input('cert_uuid'))->firstOrFail();
            $key = $this->keyManager->decryptPrivateKey($cert->key);

            $plaintext = $this->encryptor->decrypt($cmsDer, $cert, $key);

            return response()->json([
                'success' => true,
                'data' => $plaintext,
            ]);
        } catch (Throwable $e) {
            return response()->json([
                'success' => false,
                'error' => $e->getMessage(),
            ], 500);
        }
    }
}
