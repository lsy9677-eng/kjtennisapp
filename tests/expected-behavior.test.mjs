// Future acceptance criteria only. TODO is intentional; these are not reported as passing.
import test from 'node:test';
test.todo('EXPECTED: weekday tariff uses the weekday matrix row');
test.todo('EXPECTED: agreed seasonal tariff is applied consistently to booking and reporting');
test.todo('EXPECTED: refund derives from the immutable paid amount and original discount');
test.todo('EXPECTED: concurrent distinct-slot reservations cannot exceed daily limits');
test.todo('EXPECTED: administrator and recurring writes cannot silently overwrite occupied slots');
test.todo('EXPECTED: payment is verified server-side and save failure has an idempotent recovery/refund path');
